# Block I/O Events

**Description:** Captures block-level device I/O operations, providing insights into physical disk activity.

**Kernel Probes:** Attached via block layer instrumentation in the eBPF program.

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Timestamp | `datetime` | Event timestamp (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | PID | `u32` | Process ID that submitted the request |
| 3 | Command | `string` | Process name (max 16 characters) |
| 4 | Sector | `u64` | Starting sector number on disk (LBA) |
| 5 | Operation | `string` | Block operation type (see table below) |
| 6 | Size | `u64` | I/O size in bytes |
| 7 | Latency | `float` | Device latency in milliseconds (issue → completion) |
| 8 | TID | `u32` | Thread ID |
| 9 | CPU ID | `u32` | CPU where completion was processed |
| 10 | PPID | `u32` | Parent process ID |
| 11 | Device | `string` | Device number as `major:minor` identifying the partition/device |
| 12 | Queue Latency | `float` | Queue/scheduler latency in milliseconds (insert → issue); empty if unavailable |
| 13 | Command Flags | `string` | Pipe-separated REQ_* flags (e.g., `REQ_SYNC\|REQ_META`); empty if no flags set or on kernel ≥ 5.17 |
| 14 | Operation Code | `string` | Raw block operation code name (e.g., `REQ_OP_READ`, `REQ_OP_WRITE`); empty on kernel ≥ 5.17 |
| 15 | Request ID | `u64` | Monotonic per-request id, unique within a trace session and assigned at issue time. Distinguishes separate I/Os that reuse the same `(Device, Sector)` pair, which are otherwise identical apart from their timestamps |
| 16 | mono_ns | `u64` | Completion time in `CLOCK_MONOTONIC` nanoseconds (kernel `bpf_ktime_get_ns()`) — the common clock for correlating across streams. Add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock ns. |

> **Note:** Command Flags (field 13) and Operation Code (field 14) are only available on Linux kernel versions < 5.17. The `cmd_flags` field was removed from the `block_rq_complete` tracepoint in kernel 5.17+. On newer kernels (including 5.17, 6.x), these fields will always be empty. Use the Operation field (field 5) and RWBS flags to distinguish I/O types on newer kernels.

## Latency Measurement

I/O latency is tracked across the block layer request lifecycle using kernel tracepoints. The BPF program calculates two distinct types of latency to differentiate software queueing overhead from actual hardware processing time:

1. **Device Latency (Field 7)**:
   - **Calculation**: Time from `issue` to `completion` (`completion_time - issue_time`).
   - **Tracepoints**: `block_rq_issue` (records start time) and `block_rq_complete` (calculates final latency).
   - **Meaning**: Represents the time the request spent being processed by the device driver and the physical storage hardware.

2. **Queue/Scheduler Latency (Field 12)**:
   - **Calculation**: Time from `insert` to `issue` (`issue_time - insert_time`).
   - **Tracepoints**: `block_rq_insert` (records insert time) and `block_rq_complete` (calculates final queue latency based on issue time).
   - **Meaning**: Represents the time the request spent queued up in the OS scheduler waiting to be dispatched to the device.

**Key Matching Mechanism**: 
To accurately match corresponding `insert`, `issue`, and `complete` events for a single request, the tracer uses a composite key consisting of the block device number and starting sector (`(dev << 32) ^ sector`). CPU IDs are intentionally excluded from the correlation key, as an I/O request may be issued on one CPU but completed via an interrupt handled by a different CPU.

## Operation Types

Derived from the block layer `rwbs` string and normalized. When the rwbs string contains multiple flags (e.g., "WS", "RM"), the operation field contains pipe-separated values (e.g., "write|sync", "read|meta"):

| Value | Description |
|-------|-------------|
| `read` | Read operation |
| `write` | Write operation |
| `discard` | Discard/TRIM operation |
| `flush` | Cache flush operation |
| `secure_erase` | Secure erase operation |
| `none` | No operation |
| `sync` | Synchronous operation flag |
| `meta` | Metadata operation flag |
| `ahead` | Read-ahead flag |
| `prio` | High priority flag |
| `barrier` | Barrier flag (legacy) |

## Block Operation Codes (`REQ_OP_*`)

Raw operation codes from the kernel block layer:

| Code | Name | Description |
|------|------|-------------|
| 0 | `REQ_OP_READ` | Read sectors from device |
| 1 | `REQ_OP_WRITE` | Write sectors to device |
| 2 | `REQ_OP_FLUSH` | Flush volatile write cache |
| 3 | `REQ_OP_DISCARD` | Discard/TRIM sectors |
| 5 | `REQ_OP_SECURE_ERASE` | Securely erase sectors |
| 6 | `REQ_OP_WRITE_SAME` | Write same data to multiple sectors |
| 7 | `REQ_OP_ZONE_APPEND` | Append to zone (zoned devices) |
| 9 | `REQ_OP_WRITE_ZEROES` | Write zeroes to sectors |
| 10 | `REQ_OP_ZONE_OPEN` | Open a zone |
| 11 | `REQ_OP_ZONE_CLOSE` | Close a zone |
| 12 | `REQ_OP_ZONE_FINISH` | Finish a zone |
| 13 | `REQ_OP_ZONE_RESET` | Reset a zone |
| 15 | `REQ_OP_ZONE_RESET_ALL` | Reset all zones |
| 34 | `REQ_OP_DRV_IN` | Driver-specific input |
| 35 | `REQ_OP_DRV_OUT` | Driver-specific output |
| 36 | `REQ_OP_LAST` | Sentinel value |

These raw operation codes are captured in field 14 (Operation Code) on Linux kernels < 5.17 and provide the most accurate indication of the block layer operation type. On newer kernels, use field 5 (Operation) which derives the operation type from the rwbs string.

## Block Request Flags (`REQ_*`)

Command flags captured in the `Command Flags` field (field 13). Multiple flags are pipe-separated:

| Bit | Name | Description |
|-----|------|-------------|
| `0x01` | `REQ_FAILFAST_DEV` | Fail fast on device error |
| `0x02` | `REQ_FAILFAST_TRANSPORT` | Fail fast on transport error |
| `0x04` | `REQ_FAILFAST_DRIVER` | Fail fast on driver error |
| `0x08` | `REQ_SYNC` | Synchronous request |
| `0x10` | `REQ_META` | Metadata I/O |
| `0x20` | `REQ_PRIO` | High priority request |
| `0x40` | `REQ_NOMERGE` | Do not merge with other requests |
| `0x80` | `REQ_IDLE` | Idle priority request |
| `0x100` | `REQ_INTEGRITY` | Data integrity protected |
| `0x200` | `REQ_FUA` | Force Unit Access (bypass write cache) |
| `0x400` | `REQ_PREFLUSH` | Flush cache before request |
| `0x800` | `REQ_RAHEAD` | Read-ahead request |
| `0x1000` | `REQ_BACKGROUND` | Background I/O |
| `0x2000` | `REQ_NOWAIT` | Don't wait if request cannot be issued |
| `0x4000` | `REQ_CGROUP_PUNT` | Cgroup accounting |

## RWBS Flags

Character flags from the block layer tracepoint `rwbs` string. Each character in the rwbs string is decoded to its corresponding flag name, and when multiple characters are present, they are concatenated with pipes in the Operation field (field 5).

**Examples:**
- `"R"` → `"read"`
- `"WS"` → `"write|sync"`
- `"RM"` → `"read|meta"`
- `"WMA"` → `"write|meta|ahead"`

| Char | Name | Description |
|------|------|-------------|
| `R` | READ | Read operation |
| `W` | WRITE | Write operation |
| `D` | DISCARD | Discard/TRIM |
| `E` | SECURE_ERASE | Secure erase |
| `F` | FLUSH | Cache flush |
| `N` | NONE | No operation |
| `S` | SYNC | Synchronous |
| `M` | META | Metadata |
| `A` | AHEAD | Read-ahead |
| `P` | PRIO | High priority |
| `B` | BARRIER | Barrier (legacy) |

**Output File:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/ds/ds_*.csv.zst`
