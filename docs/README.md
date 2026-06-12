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
linux_trace_v3_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS traces
├── ds/                    # Block device traces
├── cache/                 # Page cache events
├── pagefault/             # Page fault events
├── io_uring/              # io_uring async I/O events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files
```

- `{MACHINE_ID}`: Uppercase machine identifier
- `{YYYYMMDD_HHMMSS_mmm}`: Timestamp with millisecond precision
