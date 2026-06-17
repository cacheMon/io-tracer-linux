# Network Events

**Description:** Captures network activity as a deliberately **low-overhead
subset**: connection lifecycle, I/O multiplexing (epoll/poll/select), socket
option changes, and packet drops/retransmissions. The high-frequency per-packet
TCP/UDP send/receive path is **not** traced, which keeps kernel-side overhead
minimal.

**Opt-in:** Network tracing is **off by default**. Enable it with `--network`.
The probes are only *compiled into* the eBPF program (via `-DENABLE_NETWORK`) and
auto-attached when this flag is set, so there is zero added overhead when it is
off.

All probes are syscall/event **tracepoints** (stable across kernel versions):

- **Connection lifecycle:** `sys_enter/exit_socket`, `sys_enter_bind`,
  `sys_enter_listen`, `sys_enter/exit_accept4`, `sys_enter/exit_connect`,
  `sys_enter_shutdown`, `sys_enter_close` (socket fds only)
- **Multiplexing:** `sys_enter/exit_epoll_create1`, `sys_enter_epoll_ctl`,
  `sys_enter/exit_epoll_wait`, `sys_enter/exit_poll`,
  `sys_enter/exit_select`, `sys_enter/exit_pselect6`
- **Socket options:** `sys_enter_setsockopt`, `sys_enter_getsockopt`
  (filtered to `SOL_SOCKET` and `IPPROTO_TCP`)
- **Drops/retransmits:** `skb:kfree_skb`, `tcp:tcp_retransmit_skb`

Each stream carries a trailing `mono_ns` column (`CLOCK_MONOTONIC` nanoseconds
from the kernel `bpf_ktime_get_ns()`) — the common cross-stream correlation
clock. Add the manifest's `clock.mono_to_real_offset_ns` to recover wall-clock
nanoseconds.

**Output Files:** Like every other trace stream, network streams are
Zstandard-compressed on disk and on upload:

- `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/nw_conn/nw_conn_*.csv.zst`
- `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/nw_epoll/nw_epoll_*.csv.zst`
- `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/nw_sockopt/nw_sockopt_*.csv.zst`
- `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/nw_drop/nw_drop_*.csv.zst`

(They are left uncompressed only when the optional `zstandard` library is
unavailable — the same fallback that applies to all streams.)

## Connection Lifecycle — `nw_conn/nw_conn_*.csv.zst`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | timestamp | `datetime` | Event time (`YYYY-MM-DD HH:MM:SS.ffffff`) |
| 2 | event_type | `string` | `SOCKET_CREATE`, `BIND`, `LISTEN`, `ACCEPT`, `CONNECT`, `SHUTDOWN`, `CLOSE` |
| 3 | pid | `u32` | Process ID |
| 4 | tid | `u32` | Thread ID |
| 5 | command | `string` | Process name (max 16 chars) |
| 6 | domain | `string` | Address family (`AF_INET`, `AF_INET6`, ...) |
| 7 | sock_type | `string` | Socket type (`SOCK_STREAM`, `SOCK_DGRAM`, ...) |
| 8 | ipver | `string` | IP version (`4` or `6`); empty if unknown |
| 9 | local_addr | `string` | Local IP address; empty if unavailable |
| 10 | remote_addr | `string` | Remote IP address; empty if unavailable |
| 11 | sport | `u16` | Local (source) port; empty if `0` |
| 12 | dport | `u16` | Remote (destination) port; empty if `0` |
| 13 | fd | `u32` | Socket file descriptor; empty if `0` |
| 14 | backlog | `u32` | `listen()` backlog; empty otherwise |
| 15 | shutdown_how | `string` | `SHUT_RD`/`SHUT_WR`/`SHUT_RDWR`; empty otherwise |
| 16 | latency_ns | `u64` | Entry→exit latency for `accept`/`connect`; empty otherwise |
| 17 | return_value | `s32` | Syscall return value |
| 18 | mono_ns | `u64` | Cross-stream correlation clock |

## Multiplexing (epoll/poll/select) — `nw_epoll/nw_epoll_*.csv.zst`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | timestamp | `datetime` | Event time |
| 2 | event_type | `string` | `EPOLL_CREATE`, `EPOLL_CTL`, `EPOLL_WAIT`, `POLL`, `SELECT` |
| 3 | pid | `u32` | Process ID |
| 4 | tid | `u32` | Thread ID |
| 5 | command | `string` | Process name |
| 6 | epoll_fd | `u32` | Epoll instance fd; empty if `0` |
| 7 | target_fd | `u32` | `epoll_ctl` target fd; empty if `0` |
| 8 | operation | `string` | `epoll_ctl` op (`EPOLL_CTL_ADD`/`MOD`/`DEL`); empty otherwise |
| 9 | event_mask | `string` | Decoded epoll event flags (`EPOLLIN|EPOLLOUT|...`) |
| 10 | max_events | `u32` | `epoll_wait` maxevents; empty otherwise |
| 11 | ready_count | `s32` | Number of ready fds (or return value) |
| 12 | timeout_ms | `u64` | Wait timeout in ms; empty otherwise |
| 13 | latency_ns | `u64` | Wait entry→exit latency; empty otherwise |
| 14 | mono_ns | `u64` | Cross-stream correlation clock |

## Socket Options — `nw_sockopt/nw_sockopt_*.csv.zst`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | timestamp | `datetime` | Event time |
| 2 | event_type | `string` | `SET` or `GET` |
| 3 | pid | `u32` | Process ID |
| 4 | command | `string` | Process name |
| 5 | fd | `u32` | Socket file descriptor |
| 6 | level | `string` | Option level (`SOL_SOCKET`, `IPPROTO_TCP`) |
| 7 | option_name | `string` | Option name (`SO_REUSEADDR`, `TCP_NODELAY`, ...) |
| 8 | optval | `s64` | Integer option value (`setsockopt` only) |
| 9 | return_value | `s32` | Syscall return value |
| 10 | mono_ns | `u64` | Cross-stream correlation clock |

## Drops & Retransmits — `nw_drop/nw_drop_*.csv.zst`

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | timestamp | `datetime` | Event time |
| 2 | event_type | `string` | `PACKET_DROP` (kfree_skb) or `TCP_RETRANSMIT` |
| 3 | pid | `u32` | Process ID in context at drop time |
| 4 | command | `string` | Process name |
| 5 | proto | `string` | L4 protocol (`TCP`, `UDP`, ...); empty if unknown |
| 6 | ipver | `string` | IP version (`4` or `6`); empty if unknown |
| 7 | src_addr | `string` | Source IP address; empty if unavailable |
| 8 | dst_addr | `string` | Destination IP address; empty if unavailable |
| 9 | sport | `u16` | Source port; empty if `0` |
| 10 | dport | `u16` | Destination port; empty if `0` |
| 11 | skb_len | `u32` | Packet length in bytes (kfree_skb only) |
| 12 | drop_reason | `u32` | Kernel drop reason code (5.17+); `0` otherwise |
| 13 | tcp_state | `string` | TCP state for retransmit events; empty otherwise |
| 14 | mono_ns | `u64` | Cross-stream correlation clock |

## Notes

- **Self-filtering:** events from the tracer's own PID are excluded in-kernel via
  the `tracer_config` map.
- **`close()` filtering:** `CLOSE` events are only emitted for file descriptors
  that were previously observed as sockets (tracked in the `socket_fds` map), so
  ordinary file closes don't appear here.
- **Not traced:** per-packet TCP/UDP `send`/`recv` and `MSG_*` flag capture are
  intentionally excluded to bound overhead.
