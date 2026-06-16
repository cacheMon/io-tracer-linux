# IO Tracer Documentation

This directory contains the complete documentation for IO Tracer's trace output, covering all captured event types, data formats, and system snapshots.

## Overview

| Document | Description |
|----------|-------------|
| [Trace Types](TRACE_TYPES.md) | Summary of all trace and snapshot types with architecture overview |
| [Trace Format](TRACE_FORMAT.md) | Detailed CSV output format specification for every trace category |


## Output Directory Structure

Traces are stored in object storage with the following prefix structure:

```
linux_trace_v4_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS traces (also receives mirrored io_uring I/O)
├── ds/                    # Block device traces
├── cache/                 # Page cache events (opt-in: --cache)
├── pagefault/             # Page fault events
├── nw_conn/               # Network connection lifecycle (opt-in: --network)
├── nw_epoll/              # Network epoll/poll/select events (opt-in: --network)
├── nw_sockopt/            # Network socket-option events (opt-in: --network)
├── nw_drop/               # Network drops/retransmits (opt-in: --network)
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

Page-cache and network streams are **off by default** (enable with `--cache` /
`--network`); when disabled their probes are never attached, so their
directories stay empty.

A self-describing `manifest.json` (schema version, per-stream columns, and clock
diagnostics) is written at the session root and delivered inside the session archive.

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision
