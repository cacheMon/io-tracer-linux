# Compatibility and Troubleshooting Fixes

This document outlines key compatibility issues resolved to allow the IO Tracer to run smoothly on older Linux kernels (e.g., Ubuntu systems with kernels `< 5.17`) and high-core-count machines.

## 1. `struct folio` Compilation Errors on Older Kernels

### The Problem
On kernel versions prior to 5.17, the `struct folio` data structure and its associated API do not exist in the Page Cache subsystem. The BPF prober (`src/tracer/prober/prober.c`) contained tracing functions like `trace_folio_mark_accessed`, `trace_folio_mark_dirty`, `trace_shrink_folio_list`, and `trace_cache_drop_folio` which referenced `struct folio`. When compiling the BPF program on older kernels, this resulted in the following error:
```c
error: incomplete definition of type 'struct folio'
```

### The Solution
We implemented selective compilation using standard kernel version macros (`#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)`).
* All probe functions referencing `struct folio` are now strictly compiled only on compatible kernels.
* On older kernels, the BPF compiler ignores the folio-based functions and falls back safely to page-based caching traces (`trace_cache_drop_page`) where applicable.

## 2. Missing `cmd_flags` in `block_rq_complete`

### The Problem
The `block_rq_complete` tracepoint arguments vary between kernel versions. On some older kernels, the `cmd_flags` variable is missing from the tracepoint format definition entirely, leading to a direct compilation failure when `args->cmd_flags` was accessed in `prober.c`.

### The Solution
Instead of relying on a hardcoded kernel version macro, which can be unreliable across backported distribution kernels, `src/tracer/IOTracer.py` now dynamically checks for the presence of `cmd_flags` by parsing the format file directly:
`/sys/kernel/debug/tracing/events/block/block_rq_complete/format`

If the keyword `cmd_flags` is found, the Python script injects a `-DHAS_CMD_FLAGS` definition into the BPF compiler (`cflags`). In `prober.c`, `cmd_flags` collection is now wrapped in an `#ifdef HAS_CMD_FLAGS` block, ensuring safe access.

## 3. "Too many open files" (File Descriptor Exhaustion)

### The Problem
When running the IO Tracer on a machine with a very high CPU core count (e.g., 56 CPUs), the system threw `perf_event_open: Too many open files` instantly at startup. Later during the trace, the Python `ProcessSampler` thread threw `OSError: [Errno 24] Too many open files` while trying to read `/proc/<pid>/stat`.

Linux default `sudo` environments often enforce a soft limit of 1024 open file descriptors.
1. The `bcc` library allocates a separate `perf_event` buffer file per CPU per tracepoint. For 56 CPUs tracking 12 events, the tracer instantiates `56 * 12 = 672` file descriptors upfront.
2. The background thread iterating over hundreds of active system processes (`psutil.process_iter`) opens additional `/proc` stat files concurrently.
When combined, the initial burst quickly saturates the 1024 limit.

### The Solution
* **RLIMIT_NOFILE Bump**: We added a booster function `maximize_fd_limit()` at the start of `iotrc.py`. By importing `resource`, the script now dynamically bypasses the default 1024 soft limit and escalates the `RLIMIT_NOFILE` to up to `1,048,576` at runtime before starting any tracing allocations.
* **psutil Context Guarding**: We improved file descriptor cleanup inside `ProcessSampler.py`. The `psutil.process_iter` iterations are now safely enclosed in protective `try/except` blocks to handle processes that disappear mid-iteration, safely closing their descriptors instead of leaking them into memory.

## 4. OS Information Dump on Compile / Run Failure

### The Problem
When the BPF prober could not compile (e.g. a kernel-version mismatch the
`#if` guards didn't cover) or failed to load/attach on an unexpected kernel,
the tracer exited with a generic *"Your device is incompatible … please notify
us"* message. The user had nothing concrete to send, and the maintainers had
nothing to act on — diagnosing the incompatibility meant a slow back-and-forth
asking for the kernel version, BTF availability, toolchain versions, and so on.

### The Solution
On any compile/load failure (`IOTracer.__init__`) or probe-attach failure
(`IOTracer.trace()`), the tracer now calls
`SystemSnapper.dump_failure_diagnostics()`, which collects **as much of the OS /
kernel / toolchain environment as possible** and writes it to a local file
named `io-tracer-os-info_<timestamp>.json` (in the current directory, falling
back to the system temp dir). A short summary is also printed to the console.

Collection is *best effort* — every probe is individually guarded, so a missing
`/proc` entry or absent tool is recorded as an error rather than aborting the
dump. The captured data includes:

* **The triggering error** and its full traceback, plus the exact `cflags` and
  BPF source path that were attempted.
* **Kernel**: `uname` fields, `/proc/version`, `/proc/cmdline` (surfaces
  BPF-blocking boot params such as `lockdown=`; secret-looking `key=value`
  tokens are redacted), and the libc version.
* **BTF**: whether `/sys/kernel/btf/vmlinux` is present (required by BCC/CO-RE).
* **Kernel config**: a curated set of BPF-relevant `CONFIG_*` values read from
  `/proc/config.gz` or `/boot/config-<release>` (`CONFIG_BPF_SYSCALL`,
  `CONFIG_DEBUG_INFO_BTF`, `CONFIG_KPROBES`, …).
* **Toolchain**: Python, `bcc`, `clang`/`llc`, `gcc`, and `ld` versions (`clang`
  is what BCC shells out to when compiling the prober).
* **Kernel headers**: presence of `/lib/modules/<release>/build` and
  `/usr/src/linux-headers-<release>` (BCC's fallback when BTF is absent).
* **tracefs**: whether debugfs/tracefs is mounted and whether the
  `block_rq_complete` tracepoint exposes `cmd_flags` (the field `-DHAS_CMD_FLAGS`
  keys off).
* **System specs**: OS/distribution, CPU, and memory. The IP-geolocation
  country lookup is intentionally skipped on this path so a slow/unreachable
  network can't delay or block the dump.

## 5. `LLVM ERROR: Invalid usage of the XADD return value` on Older LLVM/BCC Builds

### The Problem
On some machines, loading the BPF program aborted the whole process outright:
```
Loading BPF program... \ LLVM ERROR: line 3018: Invalid usage of the XADD return value
Aborted
```
No Python exception was raised — the `try/except` around BPF initialization
never fired, because this is a hard `SIGABRT` from inside LLVM itself (BCC
embeds clang/LLVM in-process rather than shelling out, so a fatal LLVM error
crashes the whole interpreter).

The cause was `prober.c`'s block-tracing code assigning a per-request id from
`__sync_fetch_and_add(gen, 1)` against a single, shared (non-per-CPU)
`BPF_ARRAY` counter. Because the *return value* of the atomic add was used
(not discarded), clang had to lower it to a BPF `XADD` with the `BPF_FETCH`
flag — a fetch-and-add variant that only newer LLVM BPF backends can legally
emit. This project pins no LLVM/clang floor anywhere (only "Kernel: Linux
5.4+" / "BCC: 0.18.0+" are documented, in `docs/TRACE_FORMAT.md`), and
distros package BCC against whatever LLVM happens to be available, so the
generated bytecode reliably crashed on older/other-distro toolchains while
working fine on the machine used for development.

### The Solution
The shared atomic counter was replaced with a `BPF_PERCPU_ARRAY` counter: each
CPU bumps its own copy with a plain (non-atomic) read-increment, and
`bpf_get_smp_processor_id()` is folded into the high bits of the id so ids
stay unique across CPUs. This removes the fetch-returning atomic entirely, so
the compiler no longer needs `BPF_FETCH`/XADD support at all — sidestepping
the LLVM-version dependency rather than trying to detect and gate around it.
Nothing downstream depended on strict global monotonic ordering of `req_id`,
only on per-request uniqueness/correlation, so the change is behavior-neutral
for consumers.
