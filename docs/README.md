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
├── cache/                 # Page cache events
├── pagefault/             # Page fault events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
├── system_spec/           # System specification files
└── manifest.json          # Self-describing schema for this session
```

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision
