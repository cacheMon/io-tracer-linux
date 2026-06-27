# Tracer Profiling

This document describes how to profile the IO Tracer's userspace hot path and
records the findings from a baseline run.

## Why profile userspace?

The live tracer needs root, BCC/eBPF, and a real kernel, so it can't be run on
an ordinary dev box or in CI. But the throughput ceiling that matters in
practice is set in **userspace**: a single poll thread (`PollingThread`) drains
the per-CPU kernel perf buffers and runs a Python callback
(`IOTracer._print_event` and friends) for every event. If that callback can't
keep up, the kernel buffers overflow and events are *dropped* (the
`lost_events` counter in `manifest.json`). Every microsecond shaved off
per-event processing directly raises the event rate the tracer can sustain
before it starts losing data.

So the thing worth profiling is the per-event Python path:

```
poll thread
  └─ _print_event(cpu, data, size)          # one call per VFS event
       ├─ b["events"].event(data)           # ctypes decode (owned by BCC)
       ├─ flag_mapper.format_vfs_flags(...)  # flag decoding
       ├─ flag_mapper.format_fs_type(...)
       ├─ _event_walltime(...)               # ns → datetime
       ├─ _read_cmdline_cached(...)          # cached /proc read
       ├─ format_csv_row(... 22 fields ...)  # CSV row build
       └─ writer.append_fs_log(row)          # deque append + maybe flush/compress
```

## The harness

[`scripts/profile_tracer.py`](../scripts/profile_tracer.py) drives the real
callbacks with synthetic events and measures them under `cProfile`. It stubs
out `bcc` (so the module imports without a kernel), constructs an `IOTracer`
via `__new__` with only the attributes the callbacks need, and wires up the
real `FlagMapper`, `PathResolver`, and `WriteManager` (upload disabled, output
to a temp dir). Events are fed straight into `_print_event` /
`_print_event_cache` / `_print_event_block`, so every per-event function the
live tracer runs is exercised and attributed.

**What it measures:** all per-event Python processing, plus `WriteManager`
buffering, rotation, and zstd/gzip compression of the rotated files.

**What it does not measure:** the kernel BPF programs themselves, the
perf-buffer ctypes decode (`event(data)`, which lives inside BCC), and real
network latency to the upload backend. The synthetic event mix is
read/write-heavy with a small working set of pids/inodes/files, which models a
busy host where the cmdline and inode→path caches stay warm.

### Running it

```bash
# Accurate throughput (cProfile off) for each stream:
python3 scripts/profile_tracer.py --stream fs    -n 300000 --bench
python3 scripts/profile_tracer.py --stream cache -n 300000 --bench
python3 scripts/profile_tracer.py --stream block -n 300000 --bench

# Per-function breakdown (cProfile on):
python3 scripts/profile_tracer.py --stream fs -n 200000 --sort tottime --top 25

# Isolate per-event cost from flush/compress:
python3 scripts/profile_tracer.py --stream fs -n 300000 --bench --no-compress

# Dump raw stats for snakeviz / pstats:
python3 scripts/profile_tracer.py --dump /tmp/fs.pstats
```

`--bench` disables `cProfile` (which inflates per-call cost ~5×) so the
events/s number is representative; the per-function table needs `cProfile` on.

## Baseline results

Measured on the CI/dev container (CPython, `cProfile` off for throughput, on
for the breakdown). Absolute rates are machine-relative — the **relative**
breakdown is the durable signal.

### Throughput by stream

| Stream | Throughput   | Per-event | Notes                                  |
|--------|--------------|-----------|----------------------------------------|
| fs     | ~67k ev/s    | ~14.9 µs  | compress on (rotates + zstd)           |
| fs     | ~78k ev/s    | ~12.8 µs  | `--no-compress` (pure per-event)       |
| cache  | ~145k ev/s   | ~6.9 µs   | smallest row, fewest flag lookups      |
| block  | ~129k ev/s   | ~7.8 µs   | rwbs/dev decode                        |

The fs/VFS stream is roughly **2× more expensive per event** than cache or
block, because it builds the widest CSV row (22 columns) and does the most flag
decoding. It is also the highest-volume stream on most hosts, so it dominates
total userspace cost.

### Where the fs per-event time goes (`tottime`, 200k events)

```
ncalls   tottime  function
200000    2.18s   utils.format_csv_row              # 22-field CSV build
200000    2.05s   IOTracer._print_event             # the callback body itself
200000    1.30s   FlagMapper.format_fs_flags        # open-flag decode
4.8M      0.38s   list.append
200000    0.30s   WriterManager.append_fs_log       # deque append + flush check
200000    0.17s   FlagMapper.format_fs_type
200000    0.14s   IOTracer._ns_to_walltime          # ns → datetime
400000    0.14s   str.join
200000    0.12s   IOTracer._format_dev
200000    0.11s   {built-in fromtimestamp}
```

Three leaves account for the bulk of attributable time:
`format_csv_row` (~27%), the `_print_event` body (~25%), and
`format_fs_flags` (~16%).

## Findings & optimization opportunities

These are recorded for follow-up. They are **not applied here** — this change
is profiling only, and several touch the trace output format, which deserves
its own review. Impact figures are measured against the baseline above.

1. **`format_fs_flags` loops the full flag table even when `flags == 0`.**
   On a read/write/close-heavy mix the overwhelmingly common argument is
   `flags == 0`, yet the function still iterates all 19 entries of
   `flag_fs_map` and runs per-entry list-membership scans
   (`name in [...]`, `"O_DSYNC" in result`). A short-circuit —
   `if flags == 0: return "O_RDONLY"` — is exactly equivalent (access mode 0 =
   `O_RDONLY`, no other bits set) and is **~25× faster on that path**
   (2460 ns → 96 ns per call, microbenchmarked). Since `format_fs_flags` is
   ~16% of fs `tottime`, this alone is a meaningful win. The general path could
   also precompute the non-access flag list once instead of re-filtering the
   dict per call.

2. **`format_csv_row` is the single biggest leaf.** It is already hand-rolled
   to avoid the stdlib `csv` overhead, but per field it does a type check and a
   special-character scan. Most of the 22 fields per row are empty strings or
   ints. Options worth measuring: skip the special-char scan for fields known
   never to contain `,"\n\r` (op name, numeric columns), or assemble the row
   from a pre-sized list. This is the highest-volume function in the tracer, so
   even a small per-field saving compounds.

3. **A `datetime` is built and stringified per event.** `_event_walltime` →
   `_ns_to_walltime` calls `datetime.fromtimestamp(...)` and the result is then
   `str()`-formatted inside `format_csv_row` (~0.4s cumulative / 200k events).
   The raw monotonic-ns value is *already* emitted as the row's last column, so
   the human-readable timestamp is partially redundant. Consider formatting the
   wall-clock string directly from integer ns (avoiding the `datetime` object),
   or making the formatted timestamp optional.

4. **Repeated `getattr(event, "x", 0)` / `hasattr(event, "x")` guards.**
   `_print_event` does ~6 `getattr`/`hasattr` probes per event (1.2M `getattr`
   + 0.6M `hasattr` calls for 200k events) to tolerate optional struct fields.
   Since the struct layout is fixed once the BPF program is compiled, these
   could be resolved once at startup (e.g. capture the field set from
   `event._fields_`) rather than per event.

5. **`format_fs_type` does `dict.get` with an f-string default per call.** The
   `f"FS(0x{int(magic):x})"` default is built eagerly even on the common cache
   hit. A two-step lookup (check membership, format only on miss) avoids the
   per-event f-string allocation.

None of these change *what* is traced — only how fast each event is turned into
a CSV row. Item 1 is the cleanest first step: large, isolated, and behavior
preserving.
