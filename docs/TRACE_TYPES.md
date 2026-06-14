# Trace Types and Collection Methods

IO Tracer uses eBPF/BPF technology to intercept kernel functions and collect various types of I/O events. The tracer is composed of multiple real-time trace types and snapshot types that provide system context.

## Real-Time Trace Types

| # | Trace Type | Description | Output |
|---|------------|-------------|--------|
| 1 | [VFS Events](traces/VFS_EVENTS.md) | File system operations at the VFS layer | `fs/fs_*.csv` |
| 2 | [Block I/O Events](traces/BLOCK_IO_EVENTS.md) | Block-level device I/O operations | `ds/ds_*.csv` |
| 3 | [Page Cache Events](traces/PAGE_CACHE_EVENTS.md) | Page cache hits, misses, writebacks, evictions | `cache/cache_*.csv` |
| 4 | [Page Fault Events](traces/PAGE_FAULT_EVENTS.md) | File-backed page faults from mmap access | `pagefault/pagefault_*.csv` |

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
│  │                  │    • ds/*.csv.zst (block events)        │  │
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
- **Cache tracing** can generate high event rates; use sampling for long traces
- **Snapshots** are lightweight and only captured at trace start (except periodic process snapshots)
