# Page Fault Events

**Description:** Captures file-backed page faults that occur when accessing memory-mapped files, providing insights into mmap I/O patterns.

**Kernel Probes Attached:**
- `filemap_fault` — File-backed page fault handler (via tracepoint)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | pid | `u32` | Process ID |
| 3 | tid | `u32` | Thread ID |
| 4 | command | `string` | Process name (max 16 characters) |
| 5 | fault_type | `string` | Access type that triggered the fault (see table below) |
| 6 | severity | `string` | Fault severity (see table below) |
| 7 | inode | `u64` | Backing file inode number; empty if `0` (anonymous mapping) |
| 8 | offset_pages | `u64` | File offset in pages (`pgoff`); empty if `0` |
| 9 | address | `hex string` | Faulting virtual address (e.g., `0x7f4a3b2c1000`); empty if `0` |
| 10 | device_id | `u32` | Device ID from the file's superblock; empty if `0` |
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

**Output File:** `linux_v1/{MACHINE_ID}/{TIMESTAMP}/pagefault/pagefault_*.csv.zst`
