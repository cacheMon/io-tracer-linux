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
linux_v1/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS traces (also receives mirrored io_uring I/O)
├── block/                 # Block device traces
├── cache/                 # Page cache events (auto-enabled on capable hosts; force with --cache)
├── nw_conn/               # Network connection lifecycle (auto-enabled on capable hosts; force with --network)
├── nw_sockopt/            # Network socket-option events (auto-enabled on capable hosts; force with --network)
├── nw_drop/               # Network drops/retransmits (auto-enabled on capable hosts; force with --network)
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

Page-cache and network streams **auto-enable on a capable host** where the
overhead is affordable: page-cache requires >=8 logical cores and >=16 GB RAM,
and network additionally requires a >=10 Mbps link. On smaller hosts they stay
off. The `--cache` / `--network` flags **force** them on regardless of host
resources (always honored). When a stream is enabled its probes attach for the
whole session and, like the other continuous streams, it rotates and uploads
mid-trace rather than only flushing at shutdown; only when a stream is disabled
are its probes never attached and its directory left empty.

A self-describing `manifest.json` (schema version, per-stream columns, and clock
diagnostics) is written at the session root and delivered inside the session archive.

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision
