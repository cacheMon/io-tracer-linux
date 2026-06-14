# Filesystem Snapshot

**Description:** Records the state of the filesystem at trace start and periodically during the trace, capturing file paths, sizes, and timestamps.

**Collection Method:**
- First snapshot runs at trace start
- Subsequent snapshots are captured every hour (3600 seconds)
- Walks the filesystem hierarchy starting from `/`
- Records files up to configurable depth (default: 3)
- Skips files on different filesystems/devices
- Tracks visited inodes to avoid duplicates (hard links)
- Can operate in anonymous mode (hashes file paths)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Snapshot Timestamp | `datetime` | Time when this snapshot was taken (`YYYY-MM-DD HH:MM:SS`) |
| 2 | File Path | `string` | Full file path (or hashed path in anonymous mode) |
| 3 | Size | `integer` | File size in bytes |
| 4 | Creation Time | `datetime` | File creation time (`st_birthtime`); falls back to `st_mtime` if unavailable |
| 5 | Modification Time | `datetime` | Last data modification time (`st_mtime`) |
| 6 | Access Time | `datetime` | Last access time (`st_atime`) |
| 7 | mono_ns | `u64` | Snapshot time in `CLOCK_MONOTONIC` nanoseconds (`time.monotonic_ns()`, captured once per snapshot) — the common cross-stream correlation clock; add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

## Excluded Filesystems

Files on virtual/pseudo filesystems are automatically excluded by skipping different device IDs. The following filesystem types are not traversed:

| Filesystem | Description |
|------------|-------------|
| `procfs` | `/proc` — process information |
| `sysfs` | `/sys` — kernel/device configuration |
| `tmpfs` | In-memory temporary filesystem |
| `devtmpfs` | `/dev` — device nodes |
| `devpts` | Pseudo-terminal devices |
| `debugfs` | `/sys/kernel/debug` — debug filesystem |

## Anonymous Mode

When `--anonymous` is enabled, file paths are hashed using a deterministic hash function (12-character hash). Directory structure is preserved but individual path components are replaced with hashes. File extensions are kept for analysis purposes.

**Output File:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/filesystem_snapshot/filesystem_snapshot_part####_TIMESTAMP_DEVICEID*.csv.gz`

## Multi-Part Files

To optimize memory usage during large filesystem scans, snapshots are automatically split into multiple compressed parts:

**File Naming:** `filesystem_snapshot_part####_TIMESTAMP_DEVICEID.csv.gz`

- Part numbers are zero-padded (e.g., `part0001`, `part0002`, ...)
- Each part is compressed with gzip immediately after writing
- TIMESTAMP format: `YYYYMMDD_HHMMSS`
- DEVICEID: Uppercase machine identifier

**Completion Marker:** The final part is renamed to indicate completion:

- Format: `filesystem_snapshot_part####_TIMESTAMP_DEVICEID_complete_partsN.csv.gz`
- The `_complete_partsN` suffix indicates this is the last part, where N is the total number of parts
- Example: `filesystem_snapshot_part0003_20260214_120000_ABC123_complete_parts3.csv.gz` means 3 parts total and this is the final one

**Reading Multi-Part Snapshots:**
1. Locate all parts with matching TIMESTAMP and DEVICEID
2. Sort parts by part number
3. Verify the last part has the `_complete_partsN` suffix
4. Decompress and concatenate all parts in order

For detailed implementation information, see [Multi-Part Filesystem Snapshot Documentation](../MULTIPART_FILESYSTEM_SNAPSHOT.md).

## Incomplete Snapshot Handling

If the tracer is stopped while a filesystem snapshot is in progress:
- The snapshot **will NOT be marked as complete**
- The incomplete snapshot will **NOT** be uploaded to storage
- All incomplete part files are deleted from disk
- A warning is logged: "Skipping incomplete filesystem snapshot upload (snapshot in progress)"
- This ensures only complete, valid filesystem snapshots are preserved

The system detects interruptions by checking if the filesystem scan completed naturally before marking it as complete.

Complete snapshots (with the `_complete_partsN` suffix) are always uploaded normally.

