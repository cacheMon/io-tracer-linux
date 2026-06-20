# Trace Types and Collection Methods

IO Tracer uses eBPF/BPF technology to intercept kernel functions and collect various types of I/O events. The tracer is composed of multiple real-time trace types and snapshot types that provide system context.

## Real-Time Trace Types

| # | Trace Type | Description | Output |
|---|------------|-------------|--------|
| 1 | [VFS Events](traces/VFS_EVENTS.md) | File system operations at the VFS layer | `fs/fs_*.csv.zst` |
| 2 | [Block I/O Events](traces/BLOCK_IO_EVENTS.md) | Block-level device I/O operations | `block/block_*.csv.zst` |
| 3 | [Page Cache Events](traces/PAGE_CACHE_EVENTS.md) | Page cache hits, misses, writebacks, evictions | `cache/cache_*.csv.zst` |
| 4 | [Page Fault Events](traces/PAGE_FAULT_EVENTS.md) | File-backed page faults from mmap access | `pagefault/pagefault_*.csv.zst` |
| 5 | [Network Events](traces/NETWORK_EVENTS.md) | Connection lifecycle, socket options, drops | `nw_conn/*.csv.zst`, `nw_sockopt/*.csv.zst`, `nw_drop/*.csv.zst` |

> Per-stream files are written as `.csv.zst` (Zstandard), falling back to
> `.csv.gz` (gzip) when the `zstandard` library is unavailable.

> **Auto-enabled streams.** Page-cache and network tracing **auto-enable on a
> capable host** where the overhead is affordable: page-cache needs >=8 logical
> cores AND >=16 GB RAM; network additionally requires a >=10 Mbps link. On
> smaller hosts they stay off. The `--cache` / `--network` flags **force them on
> regardless of host resources** (always honored). When a stream is disabled its
> kernel probes are never attached (network probes are not even compiled in), so
> there is zero added overhead. The network stream is a deliberately low-overhead
> **subset** — per-packet TCP/UDP send/recv is *not* traced.

## Snapshot Types

| # | Snapshot Type | Description | Output |
|---|--------------|-------------|--------|
| 1 | [Filesystem Snapshot](traces/FILESYSTEM_SNAPSHOT.md) | Filesystem state (paths, sizes, timestamps) | `filesystem_snapshot/*.csv.zst` |
| 2 | [Process Snapshot](traces/PROCESS_SNAPSHOT.md) | Running process information | `process/*.csv.zst` |
| 3 | [System Snapshot](traces/SYSTEM_SNAPSHOT.md) | Hardware and software specifications | `system_spec/*.json` |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        IO Tracer                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │  eBPF Program   │  ◄── Kernel probes (kprobes/kretprobes)  │
│  │  (prober.c)     │                                           │
│  └────────┬────────┘                                           │
│           │ Perf buffer                                        │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  IOTracer.py     │───►│  Event Callbacks                 │  │
│  │                  │    │ - _print_event (VFS)              │  │
│  │  Trace Types:    │    │ - _print_event_block (Block)      │  │
│  │  • VFS Events    │    │ - _print_event_cache (Cache)      │  │
│  │  • Block Events  │    │ - _print_event_pagefault (Fault)  │  │
│  │  • Cache Events  │                                          │
│  │  • Page Faults   │                                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  Snapper Classes │    │  Snapshots                        │  │
│  │                  │    │ - FilesystemSnapper              │  │
│  │  Snapshots:      │    │ - ProcessSnapper                 │  │
│  │  • Filesystem    │    │ - SystemSnapper                  │  │
│  │  • Process       │    └─────────────────────────────────┘  │
│  │  • System        │                                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │  WriterManager  │    Output:                               │
│  │                  │    • fs/*.csv.zst (VFS events)          │  │
│  │                  │    • block/*.csv.zst (block events)     │  │
│  │                  │    • cache/*.csv.zst (cache events)     │  │
│  │                  │    • pagefault/*.csv.zst (page faults)  │  │
│  │                  │    • filesystem_snapshot/*.csv.zst      │  │
│  │                  │    • process/*.csv.zst                  │  │
│  │                  │    • system_spec/*.json                 │  │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Considerations

- **VFS tracing** has moderate overhead as it captures every file operation
- **Block tracing** is essential for understanding physical I/O patterns
- **Cache tracing** auto-enables on a capable host (>=8 logical cores AND >=16 GB
  RAM) and can be forced on with `--cache`; it can generate very high event rates
  (cache hit/miss fire on nearly every page access), so use `cache_sample_rate`
  sampling for long traces
- **Network tracing** auto-enables on a capable host (>=8 logical cores, >=16 GB
  RAM, and a >=10 Mbps link) and can be forced on with `--network`; it is a
  low-overhead subset: connection lifecycle, socket options, and
  drops/retransmits. The high-frequency per-packet send/recv path is omitted to
  keep overhead minimal
- **Snapshots** are lightweight and only captured at trace start (except periodic process snapshots)
