# Multi-Part Filesystem Snapshot Implementation

## Overview

The filesystem snapshot feature now supports splitting large filesystem scans into multiple compressed parts to optimize memory usage.

## How It Works

### File Naming Convention

Each part of a filesystem snapshot follows this naming pattern:

```
filesystem_snapshot_part####_TIMESTAMP_DEVICEID.csv.zst
```

Where:
- `part####`: Zero-padded part number (e.g., `part0001`, `part0002`, ...)
- `TIMESTAMP`: Snapshot start time in `YYYYMMDD_HHMMSS` format
- `DEVICEID`: Uppercase machine identifier

### Completion Marker

The final part is renamed to indicate completion:

```
filesystem_snapshot_part####_TIMESTAMP_DEVICEID_complete_partsN.csv.zst
```

The `_complete_partsN` suffix indicates:
- This is the last part of the snapshot
- `N` is the total number of parts in this snapshot

### Example

A 3-part filesystem snapshot might produce these files:

```
filesystem_snapshot_part0001_20260214_120000_ABC123DEF456.csv.zst
filesystem_snapshot_part0002_20260214_120000_ABC123DEF456.csv.zst
filesystem_snapshot_part0003_20260214_120000_ABC123DEF456_complete_parts3.csv.zst
```

## Compression

Files are compressed using **Zstandard** (`.zst`) for reliable and efficient compression.

## Implementation Details

### WriterManager Changes

1. **New Instance Variables**:
   - `fs_snapshot_part_number`: Tracks current part number
   - `fs_snapshot_timestamp`: Snapshot session timestamp
   - `fs_snapshot_device_id`: Machine/device identifier
   - `fs_snapshot_session_active`: Whether a snapshot session is active

2. **New Methods**:
   - `start_fs_snapshot_session()`: Initialize a new snapshot session
   - `mark_fs_snapshot_complete()`: Rename final part with completion marker

3. **Modified Methods**:
   - `flush_fssnap_only()`: Now writes to part-based files with Zstandard compression

### FilesystemSnapper Changes

The `filesystem_snapshot()` method now calls `mark_fs_snapshot_complete()` after completing the scan to mark the final part.

### Utils Changes

Uses the existing `compress_file_zstd()` helper that:
- Compresses files using Zstandard
- Removes the original uncompressed file after compression

## Buffer Flushing

The filesystem snapshot buffer is flushed when it reaches the threshold (`fs_snap_max_events`, default 80000 entries). Each flush creates a new part file. This prevents memory overflow during large filesystem scans.

## Memory Optimization

By splitting snapshots into parts:
- Memory usage is bounded by the buffer size
- Each part is compressed immediately after writing
- Original uncompressed files are removed after compression
- Large filesystem scans can complete without memory issues

## Reading Multi-Part Snapshots

To reconstruct a complete snapshot:

1. Locate all parts with matching `TIMESTAMP` and `DEVICEID`
2. Sort parts by part number
3. Verify the last part has the `_complete_partsN` suffix
4. Decompress and concatenate all parts in order

The total number of parts is indicated by the `N` value in the completion marker.

## Incomplete Snapshot Handling

### Problem

When a user stops the tracer while a filesystem snapshot is in progress, the snapshot is incomplete and should not be uploaded or included in the final trace output. Uploading partial snapshots could lead to:
- Incomplete or misleading data in analysis
- Confusion about which files were actually present
- Wasted storage space for unusable data

**Original Bug**: The system was marking interrupted snapshots as "complete" even when stopped mid-scan.

### Solution

The system now properly detects incomplete snapshots at multiple levels:

1. **Snapshot Detection** (FilesystemSnapper):
   - `filesystem_snapshot()` returns `False` if interrupted by checking the `self.interrupt` flag
   - Only calls `flush_fssnap_only()` and `mark_fs_snapshot_complete()` if the scan finished naturally
   - If interrupted, doesn't flush or mark as complete

2. **Session Tracking** (WriterManager):
   - Tracks snapshot state with `fs_snapshot_session_active` flag
   - Set to `True` when `start_fs_snapshot_session()` is called
   - Set to `False` only when `mark_fs_snapshot_complete()` is called
   - Flag remains `True` if snapshot was interrupted

3. **Shutdown Behavior** (WriterManager.force_flush()):
   - Checks if `fs_snapshot_session_active` is still `True` during shutdown
   - If active (incomplete snapshot):
     - Logs a warning: "Skipping incomplete filesystem snapshot upload (snapshot in progress)"
     - Deletes all incomplete part files from disk
     - Clears the pending upload list
     - Clears the filesystem snapshot buffer
   - If not active (complete or no snapshot):
     - Proceeds normally with compression and upload

4. **Benefits**:
   - No incomplete snapshots are ever uploaded to storage
   - No false "snapshot complete" messages for interrupted scans
   - Disk space is reclaimed by removing incomplete parts
   - Users receive clear feedback about skipped incomplete data
   - Complete snapshots are unaffected and upload normally

### Implementation

**FilesystemSnapper Detection:**
```python
# In FilesystemSnapper.filesystem_snapshot():
scan_dir(self.root_path, 0)

# Only flush and mark complete if not interrupted
if not self.interrupt:
    self.wm.flush_fssnap_only()
    self.wm.mark_fs_snapshot_complete()
    return True
else:
    # Snapshot was interrupted - don't mark as complete
    return False
```

**WriterManager Cleanup:**
```python
# In WriterManager.force_flush():
if not self.fs_snapshot_session_active:
    self.compress_log(self.output_fs_snapshot_file)
else:
    logger("warning", "Skipping incomplete filesystem snapshot upload (snapshot in progress)")
    # Delete incomplete snapshot part files from disk
    for part_file in self.fs_snapshot_parts_pending_upload:
        try:
            if os.path.exists(part_file):
                os.remove(part_file)
        except Exception as e:
            logger("error", f"Failed to remove incomplete snapshot part {part_file}: {e}")
    # Clear incomplete snapshot parts and buffer
    self.fs_snapshot_parts_pending_upload.clear()
    self.fs_snap_buffer.clear()
```

## Dependencies

This feature requires:
- All parts must have consistent timestamp and device ID
- Zstandard support via the `zstandard` package (see `requirements.txt`)
