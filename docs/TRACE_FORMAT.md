# Trace Output Format Documentation

This document describes the CSV output format for all trace types produced by io-tracer-linux.

The on-disk schema is defined once, in [`src/tracer/schema.py`](../src/tracer/schema.py),
which is the single source of truth. The CSV header rows written by `WriteManager`
and the per-session `manifest.json` are both derived from it, so the column lists
below mirror that module. Bump `SCHEMA_VERSION` there whenever columns change.

## Output Structure

Traces are uploaded to object storage with the following prefix structure:

```
linux_trace_v4_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS (Virtual File System) traces
├── ds/                    # Block device traces
├── cache/                 # Page cache events
├── pagefault/             # Memory-mapped page fault events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision

A self-describing `manifest.json` is also produced for each session (see below).

Each subdirectory contains CSV files that are automatically compressed to `.csv.zst`
(Zstandard) format. Every CSV begins with a header row, and every stream carries a
trailing `mono_ns` column (`CLOCK_MONOTONIC` nanoseconds) — the common clock for
correlating records across streams.

> **io_uring:** there is no separate `io_uring/` output stream. io_uring read/write
> I/O bypasses the VFS probes, so it is mirrored into the `fs/` (VFS) trace instead.
> See [IO_URING_EVENTS.md](traces/IO_URING_EVENTS.md).

### manifest.json

A `manifest.json` is written once per session at the session-directory root. It embeds
`schema_version`, the full column list (name, type, unit, description) for every stream,
and runtime diagnostics (per-stream row counts, the `CLOCK_MONOTONIC`→`CLOCK_REALTIME`
offset used to derive wall-clock timestamps, etc.). It is delivered inside the session's
compressed archive (a `.tar.zst` of the session directory) rather than as a standalone
object under the prefix. Consumers should read the schema from `manifest.json` rather
than hard-coding column positions.

---

## 1. VFS (Virtual File System) Traces

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/fs/fs_*.csv.zst`

**Description:** Captures all file system operations at the VFS layer, including reads, writes, opens, closes, and metadata operations. Also receives io_uring READ/WRITE rows mirrored from the io_uring instrumentation.

### CSV Header

```csv
timestamp,operation,pid,command,filename,size_requested,inode,flags,offset,tid,mmap_prot,mmap_flags,address,cmdline,return_value,errno,bytes_completed,duration_ns,device,ppid,container_id,fs_type,mono_ns
```

`return_value`, `errno`, `bytes_completed`, and `duration_ns` are populated for `READ`/`WRITE`; `device`, `ppid`, `container_id`, and `fs_type` are populated for `READ`/`WRITE`/`OPEN`. All are empty for operations that do not carry them.

For operations captured and examples, see [VFS_EVENTS.md](traces/VFS_EVENTS.md).

---

## 2. Block Device Traces

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/ds/ds_*.csv.zst`

**Description:** Captures block layer I/O operations with latency measurements from issue to completion.

### CSV Header

```csv
timestamp,pid,command,sector,operation,size,latency_ms,tid,cpu_id,ppid,device,queue_latency_ms,command_flags,operation_code,request_id,mono_ns
```

`command_flags` and `operation_code` are empty on kernel ≥ 5.17. For operations captured and examples, see [BLOCK_IO_EVENTS.md](traces/BLOCK_IO_EVENTS.md).

---

## 3. Cache Events

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/cache/cache_*.csv.zst`

**Description:** Captures page cache operations including hits, misses, dirty pages, writeback, and evictions.

### CSV Header

```csv
timestamp,pid,command,event_type,inode,page_index,size_pages,cpu_id,device_id,count,mono_ns
```

For event types and examples, see [PAGE_CACHE_EVENTS.md](traces/PAGE_CACHE_EVENTS.md).

---

## 4. Page Fault Events

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/pagefault/pagefault_*.csv.zst`

**Description:** Captures file-backed page faults from memory-mapped I/O operations. Tracks which memory accesses trigger disk reads (major faults) vs cache hits (minor faults).

### CSV Header

```csv
timestamp,pid,tid,command,fault_type,severity,inode,offset_pages,address,device_id,mono_ns
```

For fault types and examples, see [PAGE_FAULT_EVENTS.md](traces/PAGE_FAULT_EVENTS.md).

---

## 5. Process Snapshots

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/process/process_*.csv.zst`

**Description:** Periodic snapshots of all running processes (captured every 5 minutes by default).

### CSV Header

```csv
timestamp,pid,name,cmdline,vms_kb,rss_kb,creation_time,cpu_5s,cpu_2m,cpu_1h,status,mono_ns
```

For field details and examples, see [PROCESS_SNAPSHOT.md](traces/PROCESS_SNAPSHOT.md).

---

## 6. Filesystem Snapshots

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/filesystem_snapshot/filesystem_snapshot_*.csv.zst`

**Description:** Periodic directory tree snapshots showing file metadata (captured hourly by default). Large scans are split into multiple parts — see [MULTIPART_FILESYSTEM_SNAPSHOT.md](MULTIPART_FILESYSTEM_SNAPSHOT.md).

### CSV Header

```csv
snapshot_timestamp,file_path,size,creation_time,modification_time,access_time,mono_ns
```

For field details and examples, see [FILESYSTEM_SNAPSHOT.md](traces/FILESYSTEM_SNAPSHOT.md).

---

## 7. System Specification Files

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/system_spec/`

These are JSON files capturing system hardware and configuration at trace start:

- **cpu_info.json** - CPU model, cores, frequency
- **memory_info.json** - Total RAM, available memory
- **disk_info.json** - Storage devices and partitions
- **network_info.json** - Network interfaces and addresses
- **os_info.json** - Kernel version, distribution, hostname

For field details, see [SYSTEM_SNAPSHOT.md](traces/SYSTEM_SNAPSHOT.md).

---

## Data Types and Conventions

### Timestamps
- `timestamp` column format: `YYYY-MM-DD HH:MM:SS.ffffff` (microsecond precision)
- Timezone: Local system time (`CLOCK_REALTIME`, derived from the kernel's `CLOCK_MONOTONIC` for perf-event streams)
- `mono_ns` column: raw `CLOCK_MONOTONIC` nanoseconds — `bpf_ktime_get_ns()` for perf-event streams, `time.monotonic_ns()` for userspace snapshots. This is the common cross-stream correlation clock.

### File Paths
- Always absolute paths when available
- Special values:
  - `[sendfile]` - sendfile() operation (no specific file)
  - Empty string - Path unavailable or unresolvable (see "Empty Filenames" section in [VFS_EVENTS.md](traces/VFS_EVENTS.md) for detailed reasons)

### Process Information
- `pid` - Process ID (TGID in kernel terms)
- `tid` - Thread ID (kernel task PID)
- `ppid` - Parent Process ID
- `command` - Truncated to 16 characters (TASK_COMM_LEN)

### Sizes and Offsets
- All sizes in bytes unless specified
- Sector count: 512-byte sectors (multiply by 512 for bytes)
- Page size: 4096 bytes (4 KiB)
- Cache `page_index` × 4096 = byte offset

### Special Values
- `0` - Not applicable or unavailable
- Empty string - Field not captured for this event type
- `NO_FLAGS` - No flags set

---

## Compression and File Rotation

### Compression
- All CSV files are automatically compressed with Zstandard
- Original `.csv` files are deleted after compression
- Final archives: `.csv.zst` format

### File Rotation
Continuous streams (VFS, block, cache, page fault) are rotated and compressed when any
of the following is reached (see `WriteManager` in `src/tracer/WriterManager.py`):
- **Event count:** ~80,000–100,000 buffered events (adaptively raised under load)
- **File age:** 20 minutes since the current file was opened
- **File size:** 100 MB uncompressed on disk

Snapshots (process, filesystem) are written as whole units rather than rotated mid-session.

File naming: `{type}_{YYYYMMDD_HHMMSS_mmm}_{seq}.csv.zst`

---

## Reading Compressed Traces

### Command Line
```bash
# View compressed file
zstd -dc fs_*.csv.zst | less

# Parse with csvkit
zstd -dc fs_*.csv.zst | csvstat

# Count events
zstd -dc fs_*.csv.zst | wc -l

# Filter specific operation
zstd -dc fs_*.csv.zst | grep ",WRITE,"
```

### Python
```python
import csv
import io
import zstandard

with open('fs_20240115_103045_123_0001.csv.zst', 'rb') as fh:
    text = io.TextIOWrapper(zstandard.ZstdDecompressor().stream_reader(fh), encoding='utf-8')
    reader = csv.DictReader(text)  # first row is the schema header
    for row in reader:
        print(f"{row['timestamp']}: {row['operation']} on {row['filename']} by {row['command']} ({row['pid']})")
```

### Pandas
```python
import glob
import pandas as pd

# pandas reads .zst natively when the `zstandard` package is installed
df = pd.read_csv('fs_20240115_103045_123_0001.csv.zst')

# Multiple files in a directory
files = glob.glob('*.csv.zst')
df = pd.concat([pd.read_csv(f) for f in files])
```

---

## Performance Considerations

### Event Rates
Expected event rates (highly workload-dependent):
- **VFS:** 1-100K events/sec
- **Block:** 100-10K events/sec
- **Cache:** 10K-1M events/sec (before sampling)

### Lost Events
If kernel buffers overflow, events may be lost. Monitor logs for warnings about lost
events in the kernel buffer.

---

## Version Information

This documentation applies to:
- **Trace schema:** version 2 (`SCHEMA_VERSION` in `src/tracer/schema.py`)
- **Kernel:** Linux 5.4+
- **BCC:** 0.18.0+

Field availability may vary by kernel version. Check logs for warnings about unavailable probes.
