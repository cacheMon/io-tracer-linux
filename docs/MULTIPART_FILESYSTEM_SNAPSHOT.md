# Multi-Part Filesystem Snapshot Implementation

## Overview

The filesystem snapshot feature now supports splitting large filesystem scans into multiple compressed parts to optimize memory usage.

## Delta Snapshots

To avoid re-uploading the entire filesystem inventory on every hourly pass, the
snapper is **delta-based after the first run**:

- The **first** snapshot of a session is a *full* inventory of every file.
- **Every subsequent** snapshot is a *delta*: a file is recorded only if it was
  **added** or **modified** (its size, `mtime`, or `ctime` changed) since the
  previous completed snapshot. Access time (`atime`) is intentionally excluded
  from the change check because it changes on every read.
- A file that **disappeared** since the previous snapshot is recorded as a
  *tombstone* row whose `size` is `-1` (`FilesystemSnapper.DELETED_SIZE`),
  letting consumers distinguish removals from added/modified files (which always
  carry a real, non-negative byte count).
- A delta with **no changes** produces no rows, so nothing is flushed or
  uploaded for that pass.

### Baseline tracking

The snapper keeps the most recent *completed* full scan in memory as the
baseline for the next delta. An interrupted scan never advances the baseline,
so after an interruption the next completed pass is diffed against the last
good snapshot (and the first ever snapshot is always full).

### Transient errors vs. real deletions

Deletion detection distinguishes "the path is gone" from "we couldn't read it
this pass". A file or directory that fails to `stat()`/`scandir()` with a
*transient* error (e.g. `PermissionError`, an I/O error) has its previous state
carried forward, so it is **not** falsely tombstoned. Only paths that are
genuinely absent — `FileNotFoundError`/`NotADirectoryError`, or a path missing
from a directory that *was* fully scanned — become tombstones. Removing an
entire directory therefore still tombstones every file under it.

### Reconstructing state from deltas

To reconstruct the filesystem state at snapshot *k*: start from the full
inventory (snapshot 0) and apply each delta `1..k` in order — added/modified
rows overwrite the entry for that path, tombstone rows (`size == -1`) remove it.

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

Files are compressed using **Zstandard** (`.zst`) for reliable and efficient compression. When the optional `zstandard` library is unavailable, the tracer falls back to **gzip** (`.gz`) from the Python standard library so snapshot parts are still compressed.

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

Uses the `compress_file()` helper that:
- Compresses files using Zstandard, falling back to gzip (`.gz`) when `zstandard` is unavailable
- Returns the compressed output path so the caller can remove the original uncompressed file

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
