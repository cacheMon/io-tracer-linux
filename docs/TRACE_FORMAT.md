# Trace Output Format Documentation

This document describes the CSV output format for all trace types produced by io-tracer-linux.

## Output Structure

Traces are uploaded to object storage with the following prefix structure:

```
linux_trace_v3_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS (Virtual File System) traces
├── ds/                    # Block device traces
├── cache/                 # Page cache events
├── pagefault/             # Memory-mapped page fault events
├── io_uring/              # io_uring async I/O events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision

Each subdirectory contains CSV files that are automatically compressed to `.csv.gz` format.

---

## 1. VFS (Virtual File System) Traces

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/fs/fs_*.csv.gz`

**Description:** Captures all file system operations at the VFS layer, including reads, writes, opens, closes, and metadata operations.

### CSV Header

```csv
timestamp,operation,pid,tid,command,filename,size,offset,bytes_completed,inode,device,flags,duration_ns,return_value,errno,mmap_prot,mmap_flags,address,cmdline,ppid,container_id,fs_type,mono_ns
```

**Schema v3 — cross-OS aligned.** Columns 1–12 (`timestamp` … `flags`) are the
**shared prefix** emitted identically by the Windows tracer's `filesystem/`
stream, so a single parser reads the comparable fields from either OS. The
remaining columns are Linux-only extras. `operation` is now a **lowercase**
canonical name (`read`, `write`, `open`, `close`, `fsync`, …). `size_requested`
was renamed to `size`.

`return_value`, `errno`, `bytes_completed`, and `duration_ns` are populated for `read`/`write`; `device`, `ppid`, `container_id`, and `fs_type` are populated for `read`/`write`/`open`. All are empty for operations that do not carry them.

For operations captured and examples, see [VFS_EVENTS.md](traces/VFS_EVENTS.md).

---

## 2. Block Device Traces

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/ds/ds_*.csv.gz`

**Description:** Captures block layer I/O operations with latency measurements from issue to completion.

### CSV Header

```csv
timestamp,operation,pid,tid,command,sector,size,latency_ms,device,flags,cpu_id,ppid,queue_latency_ms,command_flags,operation_code,request_id,mono_ns
```

**Schema v3 — cross-OS aligned.** Columns 1–10 (`timestamp` … `flags`) are the
**shared prefix** emitted identically by the Windows tracer's `ds/` stream. The
`operation` column now holds the **base op only** (`read`, `write`, `flush`,
`discard`, …); the rwbs sub-flags (`sync`, `meta`, `ahead`, …) that used to be
appended to it (e.g. `write|sync`) now live in the dedicated `flags` column.

For operations captured and examples, see [BLOCK_IO_EVENTS.md](traces/BLOCK_IO_EVENTS.md).

---

## 3. Cache Events

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/cache/cache_*.csv.gz`

**Description:** Captures page cache operations including hits, misses, dirty pages, writeback, and evictions.

### CSV Header

```csv
timestamp,pid,command,event_type,inode,index,size,cpu_id,dev_id,count
```

For event types and examples, see [PAGE_CACHE_EVENTS.md](traces/PAGE_CACHE_EVENTS.md).

---

## 4. Page Fault Events

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/pagefault/pagefault_*.csv.gz`

**Description:** Captures file-backed page faults from memory-mapped I/O operations. Tracks which memory accesses trigger disk reads (major faults) vs cache hits (minor faults).

### CSV Header

```csv
timestamp,pid,tid,command,fault_type,severity,inode,offset,address,dev_id
```

For fault types and examples, see [PAGE_FAULT_EVENTS.md](traces/PAGE_FAULT_EVENTS.md).

---

## 5. io_uring Events

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/io_uring/io_uring_*.csv.gz`

**Description:** Captures io_uring async I/O events for high-performance applications.

For CSV format and examples, see [IO_URING_EVENTS.md](traces/IO_URING_EVENTS.md).

---

## 6. Process Snapshots

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/process/process_*.csv.gz`

**Description:** Periodic snapshots of all running processes (captured every 5 minutes by default).

### CSV Header

```csv
timestamp,pid,name,cmdline,virtual_mem_kb,rss_kb,create_time,cpu_5s,cpu_2m,cpu_1h,status
```

For field details and examples, see [PROCESS_SNAPSHOT.md](traces/PROCESS_SNAPSHOT.md).

---

## 7. Filesystem Snapshots

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/filesystem_snapshot/filesystem_snapshot_*.csv.gz`

**Description:** Periodic directory tree snapshots showing file metadata (captured hourly by default).

### CSV Header

```csv
snapshot_timestamp,path,size,ctime,mtime,atime
```

For field details and examples, see [FILESYSTEM_SNAPSHOT.md](traces/FILESYSTEM_SNAPSHOT.md).

---

## 8. System Specification Files

**Location:** `linux_trace_v3_test/{MACHINE_ID}/{TIMESTAMP}/system_spec/`

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
- Format: `YYYY-MM-DD HH:MM:SS.ffffff` (microsecond precision)
- Timezone: Local system time
- Source: `datetime.datetime.today()` (Python) or `bpf_ktime_get_ns()` (eBPF)

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
- Cache index × 4096 = byte offset

### Special Values
- `0` - Not applicable or unavailable
- Empty string - Field not captured for this event type
- `NO_FLAGS` - No flags set

---

## Compression and File Rotation

### Compression
- All CSV files are automatically compressed with gzip
- Original `.csv` files are deleted after compression
- Final archives: `.csv.gz` format

### File Rotation
Files are rotated and compressed when buffers reach thresholds:
- **VFS traces:** Every 1000 events
- **Block traces:** Every 1000 events  
- **Cache traces:** Every 10000 events (before sampling)
- **Network traces:** Every 1000 events
- **Snapshots:** Each snapshot creates a new file

File naming: `{type}_{YYYYMMDD_HHMMSS_mmm}.csv.gz`

---

## Reading Compressed Traces

### Command Line
```bash
# View compressed file
zcat fs_*.csv.gz | less

# Parse with csvkit
zcat fs_*.csv.gz | csvstat

# Count events
zcat fs_*.csv.gz | wc -l

# Filter specific operation
zcat fs_*.csv.gz | grep ",WRITE,"
```

### Python
```python
import gzip
import csv

with gzip.open('fs_20240115_103045_123.csv.gz', 'rt') as f:
    reader = csv.reader(f)
    for row in reader:
        timestamp, operation, pid, command, filename, size, inode, flags, latency = row
        print(f"{timestamp}: {operation} on {filename} by {command} ({pid})")
```

### Pandas
```python
import pandas as pd
import glob

# Single file
df = pd.read_csv('fs_20240115_103045_123.csv.gz', compression='gzip')

# Multiple files in a directory
files = glob.glob('*.csv.gz')
df = pd.concat([pd.read_csv(f, compression='gzip') for f in files])
```

---

## Performance Considerations

### Event Rates
Expected event rates (highly workload-dependent):
- **VFS:** 1-100K events/sec
- **Block:** 100-10K events/sec
- **Cache:** 10K-1M events/sec (before sampling)
- **Network:** 100-100K events/sec

### Sampling
Cache events support sampling to reduce overhead:
```bash
python3 iotrc.py --cache-sample-rate 10
```

### Lost Events
If kernel buffers overflow, events may be lost. Monitor logs for:
```
[WARN] Lost N events in kernel buffer
```

Increase buffer size to reduce losses:
```bash
python3 iotrc.py --page-cnt 128  # Default: 64
```

---

## Version Information

This documentation applies to:
- **io-tracer-linux** version 1.0+
- **Kernel:** Linux 5.4+
- **BCC:** 0.18.0+

Field availability may vary by kernel version. Check logs for warnings about unavailable probes.
