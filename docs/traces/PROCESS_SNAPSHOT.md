# Process Snapshot

**Description:** Records information about all running processes periodically during the trace.

**Collection Method:**
- First snapshot runs immediately at trace start
- Subsequent snapshots are captured every 5 minutes (300 seconds)
- Uses `psutil` for process information
- Background thread samples CPU utilization over multiple intervals

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Snapshot timestamp (`YYYY-MM-DD HH:MM:SS`) |
| 2 | PID | `integer` | Process ID |
| 3 | Name | `string` | Process name |
| 4 | Command Line | `string` | Full command line (hashed to 12 characters in anonymous mode) |
| 5 | Virtual Memory | `float` | Virtual memory size in KB (VMS) |
| 6 | Resident Set Size | `float` | Resident set size in KB (RSS — physical memory used) |
| 7 | Creation Time | `datetime` | Process creation/start time |
| 8 | CPU 5s | `float` | CPU utilization % averaged over last 5 seconds |
| 9 | CPU 2m | `float` | CPU utilization % averaged over last 2 minutes |
| 10 | CPU 1h | `float` | CPU utilization % averaged over last 1 hour |
| 11 | Status | `string` | Process status (see table below) |
| 12 | mono_ns | `u64` | Snapshot time in `CLOCK_MONOTONIC` nanoseconds (`time.monotonic_ns()`, captured once per snapshot) — the common cross-stream correlation clock; add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

## Process Status Values

| Value | Description |
|-------|-------------|
| `running` | Process is currently executing on a CPU |
| `sleeping` | Process is in interruptible sleep (waiting for an event) |
| `disk-sleep` | Process is in uninterruptible sleep (waiting for I/O) |
| `stopped` | Process has been stopped (e.g., by a signal) |
| `tracing-stop` | Process is stopped by a debugger/tracer |
| `zombie` | Process has terminated but not yet been waited on by parent |
| `dead` | Process is dead (should not normally be seen) |
| `idle` | Process is idle (kernel threads) |

**Output File:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/process/process_*.csv.zst`

## Incomplete Snapshot Handling

If the tracer is stopped while a process snapshot is in progress:
- The snapshot **will NOT be marked as complete**
- The incomplete snapshot will **NOT** be uploaded to storage
- The process snapshot buffer is cleared
- A warning is logged: "Skipping incomplete process snapshot upload (snapshot in progress)"
- This ensures only complete, valid process snapshots are preserved

The system detects interruptions by checking the `running` flag during process iteration before flushing.

Each complete process snapshot is written as a separate CSV file and uploaded normally.
