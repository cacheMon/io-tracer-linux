# Trace Manifest (`manifest.json`)

Every trace session writes a `manifest.json` at the root of its output
directory. It makes the trace **self-describing**: the exact schema, the clocks,
the tracer/host versions, the session window, and collection diagnostics — so a
consumer never has to hard-code column layouts or guess which version produced a
trace.

It is written when tracing starts (so a schema exists even if the run is killed)
and rewritten at shutdown with the stop time and final diagnostics.

## Schema versioning

`schema_version` identifies the on-disk format. Consumers should read it and
adapt rather than assume a fixed layout. The current value is **`1`**
(`SCHEMA_VERSION` in `src/tracer/schema.py`).

The current format (**schema_version 1**) is the **cross-OS aligned** layout:

- The `fs`/`ds` streams use a fixed shared column prefix (identical names/order
  to the Windows tracer), **lowercase** canonical operation names, `size`
  (formerly `size_requested`), and a dedicated block `flags` column (rwbs
  sub-flags split out of `operation`).
- Every CSV file (including rotated parts) begins with a **header row** naming
  its columns — the same names listed under `streams.<key>.columns` here.
- Every record carries a trailing **`mono_ns`** column: `CLOCK_MONOTONIC`
  nanoseconds, the single clock shared across all streams for correlation
  (kernel `bpf_ktime_get_ns()` for perf-event streams; `time.monotonic_ns()` for
  the userspace snapshot streams). The wall-clock `timestamp` column is still
  column 1.

## Structure

```jsonc
{
  "schema_version": 1,
  "streams": {
    "fs":  { "subdir": "fs", "filename_prefix": "fs", "description": "...",
             "wall_clock": "CLOCK_REALTIME (derived from kernel CLOCK_MONOTONIC)",
             "columns": [ { "name": "timestamp", "type": "datetime", "unit": "", "description": "..." }, ... ] },
    "ds":  { ... }, "cache": { ... }, "pagefault": { ... },
    "process": { ... }, "filesystem_snapshot": { ... }
  },
  "tracer":  { "version": "..." },
  "machine_id": "...",
  "host":    { "platform": "...", "kernel": "...", "python": "..." },
  "clock": {
    "wall_clock": "CLOCK_REALTIME",
    "mono_clock": "CLOCK_MONOTONIC",
    "mono_to_real_offset_ns": 1700000000000000000,
    "note": "mono_ns is the common cross-stream correlation clock ..."
  },
  "session": { "started_at": "ISO-8601", "stopped_at": "ISO-8601", "duration_seconds": 123.4 },
  "diagnostics": {
    "attached_probes": [ "vfs_read", "vfs_write", "block_rq_complete", ... ],
    "lost_events":     { "fs": 0, "ds": 0 },
    "rows_written":    { "VFS": 12345, "Block": 678, ... },
    "block":           { "issued": 1000, "completed": 990, "missed": 10 }
  }
}
```

## Correlating across streams

All streams share the `mono_ns` clock, so records from different streams can be
ordered against each other directly by `mono_ns`. To convert any `mono_ns` to
wall-clock nanoseconds:

```
wall_ns = mono_ns + clock.mono_to_real_offset_ns
```

## Diagnostics — spotting collection problems

- **`lost_events`** — per-stream count of kernel perf-buffer overruns (events
  dropped before userspace read them). Non-zero means the buffer was too small
  or the consumer fell behind.
- **`rows_written`** — total rows persisted per stream. A stream with attached
  probes but `0` rows is a dead/disabled collection path.
- **`block`** — `issued`/`completed`/`missed` block requests. A high
  `missed`/`completed` ratio means the issue-tracking map was evicted under load
  (completions dropped) — the explanation if block events thin out before the
  end of a long trace.
- **`attached_probes`** — the kernel functions the tracer successfully attached
  to this session.
