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
Referencing a tracepoint `args->` field that the running kernel's format file
does not define is a direct compilation failure that aborts the whole BPF
load. (Note: mainline `block_rq_complete` has never exposed `cmd_flags` — the
field only exists on patched/vendor kernels, so on stock kernels the
`cmd_flags`/`op_code` trace columns are empty by design and classification
comes from `rwbs`.)

### The Solution
Instead of relying on a hardcoded kernel version macro, which can be unreliable
across backported distribution kernels, `src/tracer/IOTracer.py` dynamically
checks for the presence of a field by parsing the tracepoint format file
directly (checking both `/sys/kernel/debug/tracing` and `/sys/kernel/tracing`
mounts).

If the field is found, the Python script injects a feature define into the BPF
compiler `cflags`, and the corresponding `args->` access in `prober.c` is
wrapped in an `#ifdef`. The same mechanism now also gates
`skb:kfree_skb`'s `reason` field (`-DHAS_SKB_DROP_REASON`, kernel >= 5.17 or
5.15.58+ LTS backports) and `tcp:tcp_retransmit_skb`'s `state` field
(`-DHAS_TCP_RETRANSMIT_STATE`, kernel >= 4.20) for `--network` runs.

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
* **Toolchain**: Python, `bcc`, `clang`/`llc`, `gcc`, and `ld` versions (BCC
  compiles the prober in-process via libclang; the installed clang version
  still indicates the LLVM generation in play).
* **Kernel headers**: presence of `/lib/modules/<release>/build` and
  `/usr/src/linux-headers-<release>` (BCC's fallback when BTF is absent).
* **tracefs**: whether debugfs/tracefs is mounted and whether the
  `block_rq_complete` tracepoint exposes `cmd_flags` (the field `-DHAS_CMD_FLAGS`
  keys off).
* **System specs**: OS/distribution, CPU, and memory. The IP-geolocation
  country lookup is intentionally skipped on this path so a slow/unreachable
  network can't delay or block the dump.
