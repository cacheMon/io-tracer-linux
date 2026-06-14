# Page Fault Events

**Description:** Captures file-backed page faults that occur when accessing memory-mapped files, providing insights into mmap I/O patterns.

**Kernel Probes Attached:**
- `filemap_fault` — File-backed page fault handler (via tracepoint)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | PID | `u32` | Process ID |
| 3 | TID | `u32` | Thread ID |
| 4 | Command | `string` | Process name (max 16 characters) |
| 5 | Fault Type | `string` | Access type that triggered the fault (see table below) |
| 6 | Severity | `string` | Fault severity (see table below) |
| 7 | Inode | `u64` | Backing file inode number; empty if `0` (anonymous mapping) |
| 8 | Offset | `u64` | File offset in pages (`pgoff`); empty if `0` |
| 9 | Address | `hex string` | Faulting virtual address (e.g., `0x7f4a3b2c1000`); empty if `0` |
| 10 | Device ID | `u32` | Device ID from the file's superblock; empty if `0` |
| 11 | mono_ns | `u64` | Record time in `CLOCK_MONOTONIC` nanoseconds (kernel `bpf_ktime_get_ns()`) — the common cross-stream correlation clock; add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

## Fault Types

| Value | Description |
|-------|-------------|
| `READ` | Read access triggered the page fault |
| `WRITE` | Write access triggered the page fault |

## Fault Severity

| Value | Description |
|-------|-------------|
| `MAJOR` | Page not in memory — requires disk I/O to load the page |
| `MINOR` | Page already in page cache — no disk I/O needed (soft fault) |

**Output File:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/pagefault/pagefault_*.csv.zst`
