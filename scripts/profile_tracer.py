#!/usr/bin/env python3
"""
Userspace hot-path profiler for the IO Tracer.

The live tracer needs root + BCC/eBPF + a real kernel, so it cannot be profiled
on an ordinary dev box or in CI. But the part of the tracer that the project
actually controls — and that decides how many events per second a single poll
thread can drain before the kernel perf buffers overflow and drop events — is
the *userspace per-event processing*: the perf-buffer callbacks
(``_print_event`` and friends), the flag/CSV formatting they call, and the
``WriteManager`` buffering/rotation/compression behind them.

This harness drives that exact code with synthetic events and measures it under
``cProfile``. It feeds events straight into the real callback methods, so every
function the live tracer runs per event (minus the ctypes perf-struct decode,
which BCC owns) is exercised and attributed.

What it does NOT measure: the kernel BPF programs, the perf-buffer ctypes
decode (``self.b["events"].event(data)``), and real disk/network I/O latency to
the upload backend. Those are noted in the report but are outside userspace.

Usage:
    python3 scripts/profile_tracer.py                 # default 500k events
    python3 scripts/profile_tracer.py -n 1000000      # event count
    python3 scripts/profile_tracer.py --no-compress   # skip writer flush/compress
    python3 scripts/profile_tracer.py --sort tottime --top 30
    python3 scripts/profile_tracer.py --stream cache   # profile the cache callback

It runs entirely in-process with no root, BCC, or network access.
"""

import argparse
import cProfile
import io
import os
import pstats
import shutil
import sys
import tempfile
import time

# Make ``src`` importable when run from the repo root or scripts/.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


def _install_fake_bcc():
    """Stub out ``bcc`` so IOTracer imports without a kernel.

    IOTracer does ``from bcc import BPF`` at module import time. We never call
    BPF in the harness (we construct IOTracer via ``__new__`` and feed events
    directly), so a placeholder class is enough to satisfy the import.
    """
    if "bcc" in sys.modules:
        return
    import types

    mod = types.ModuleType("bcc")

    class BPF:  # noqa: N801 - mirror the real name
        def __init__(self, *a, **k):
            raise RuntimeError("fake bcc.BPF must not be instantiated in the profiler")

    mod.BPF = BPF
    sys.modules["bcc"] = mod


_install_fake_bcc()

from src.tracer.FlagMapper import FlagMapper          # noqa: E402
from src.tracer.IOTracer import IOTracer              # noqa: E402
from src.tracer.PathResolver import PathResolver      # noqa: E402
from src.tracer.WriterManager import WriteManager     # noqa: E402


class FakeEvent:
    """A stand-in for a decoded BPF perf event.

    Holds every attribute the callbacks read. ``filename``/``comm`` are bytes
    to match the real ctypes ``char[]`` fields the callbacks ``.decode()``.
    """

    __slots__ = (
        "pid", "tid", "ppid", "op", "filename", "comm", "inode", "size",
        "offset", "flags", "address", "fd", "dirfd", "mmap_prot", "mmap_flags",
        "ret_val", "latency_ns", "dev", "cgroup_id", "fs_magic", "ts",
        "old_addr", "old_size",
        # dual-path (rename/link/symlink)
        "filename_old", "filename_new", "inode_old", "inode_new",
        # cache
        "type", "index", "cpu_id", "dev_id", "count",
        # block
        "sector", "bio_size", "queue_time_ns", "cmd_flags", "op_code", "req_id",
    )

    def __init__(self, **kw):
        for s in self.__slots__:
            setattr(self, s, 0)
        self.filename = b""
        self.comm = b""
        self.filename_old = b""
        self.filename_new = b""
        for k, v in kw.items():
            setattr(self, k, v)


class _Decoder:
    """Mimics ``self.b["events"]``: ``.event(data)`` returns the data as-is."""

    @staticmethod
    def event(data):
        return data


class _FakeBPF(dict):
    """``self.b`` lookup table; every stream decodes to the passed FakeEvent."""

    def __init__(self):
        super().__init__()
        dec = _Decoder()
        for name in ("events", "events_dual", "cache_events", "bl_events",
                     "io_uring_events", "net_conn_events", "net_sockopt_events",
                     "net_drop_events"):
            self[name] = dec


# Op codes -> names come from FlagMapper.op_fs_types; build the reverse map so
# the synthetic mix uses real codes the callbacks will decode.
def _op_code(flag_mapper, name):
    for code, n in flag_mapper.op_fs_types.items():
        if n == name:
            return code
    raise KeyError(name)


def build_tracer(output_dir, compress):
    """Construct an IOTracer with only the attributes the callbacks need.

    Bypasses ``__init__`` (which loads BPF and tests the upload connection) and
    wires up the real collaborators: FlagMapper, PathResolver, and a real
    WriteManager (automatic_upload off) writing into a temp dir.
    """
    t = IOTracer.__new__(IOTracer)
    t.verbose = False
    t.anonymous = False
    t.trace_cache = True
    t.trace_network = True
    t._self_pid = -1  # never matches our synthetic pids
    t._mono_to_real_offset_ns = time.time_ns() - time.monotonic_ns()
    t.flag_mapper = FlagMapper()
    t.path_resolver = PathResolver()
    t.mmap_regions = {}
    t.cmdline_cache = {}
    t._event_count = 0
    t._maintenance_interval = 50000
    t._cmdline_cache_max = 100000
    t._lost_counts = {}

    # A real WriteManager so buffering, rotation and (optionally) compression
    # are measured. No upload manager needed when automatic_upload is False.
    t.writer = WriteManager(output_dir, upload_manager=None, automatic_upload=False)
    if not compress:
        # Neutralise compression/rotation so we isolate per-event processing +
        # buffer appends from the periodic flush+compress cost.
        t.writer.compress_log = lambda *a, **k: None
        t.writer.vfs_max_events = 10 ** 12
        t.writer.block_max_events = 10 ** 12
        t.writer.cache_max_events = 10 ** 12
    t.b = _FakeBPF()
    return t


def make_fs_events(flag_mapper, n, self_pid):
    """A realistic VFS event mix: open/close plus read/write-heavy traffic.

    Uses a small working set of pids/inodes/files so the cmdline and
    inode->path caches warm up the way they do on a real host (most events come
    from a handful of busy processes touching a handful of hot files).
    """
    READ = _op_code(flag_mapper, "READ")
    WRITE = _op_code(flag_mapper, "WRITE")
    OPEN = _op_code(flag_mapper, "OPEN")
    CLOSE = _op_code(flag_mapper, "CLOSE")
    # Weighted op stream: reads and writes dominate real I/O traces.
    pattern = ([OPEN] + [READ] * 12 + [WRITE] * 5 + [CLOSE])
    pids = [1001, 1002, 1003, 2007, 4242]
    files = [
        b"/var/lib/app/data.db",
        b"/home/user/project/main.log",
        b"/usr/lib/x86_64-linux-gnu/libc.so.6",
        b"/tmp/scratch/cache.idx",
    ]
    base_ts = time.monotonic_ns()
    events = []
    for i in range(n):
        op = pattern[i % len(pattern)]
        pid = pids[i % len(pids)]
        fname = files[i % len(files)] if op in (OPEN, CLOSE) else b""
        inode = 100000 + (i % 4)
        ev = FakeEvent(
            pid=pid, tid=pid + 7, ppid=1, op=op,
            filename=(fname if op == OPEN else b""),
            comm=b"app-worker",
            inode=inode,
            size=4096 if op in (READ, WRITE) else 0,
            offset=(i * 4096) & 0xFFFFFFF,
            flags=0o2 if op == OPEN else 0,
            fd=7 if op == OPEN else 0,
            ret_val=4096 if op in (READ, WRITE) else 0,
            latency_ns=15000 if op in (READ, WRITE) else 0,
            dev=(8 << 20) | 1,
            cgroup_id=0xABCD,
            fs_magic=0xEF53,
            ts=base_ts + i * 1000,
        )
        # Pre-seed the inode->path cache for read/write so the OPEN path that
        # populated it on the real host is reflected here too.
        events.append(ev)
    # Warm the inode cache the way OPEN events would, so READ/WRITE rows resolve.
    return events


def make_cache_events(n, self_pid):
    base_ts = time.monotonic_ns()
    out = []
    for i in range(n):
        out.append(FakeEvent(
            pid=1001 + (i % 5), comm=b"app-worker", type=i % 10,
            inode=100000 + (i % 8), index=i & 0xFFFF, size=4096,
            cpu_id=i % 8, dev_id=(8 << 20) | 1, count=1,
            ts=base_ts + i * 500,
        ))
    return out


def make_block_events(n, self_pid):
    base_ts = time.monotonic_ns()
    out = []
    for i in range(n):
        # The block callback also reads sector/bio_size/queue_time_ns/cmd_flags/
        # op_code/req_id; pass them straight to the constructor (all are in
        # FakeEvent.__slots__).
        out.append(FakeEvent(
            pid=1001 + (i % 5), tid=2001 + (i % 5), ppid=1,
            comm=b"app-worker", op=b"R" if i % 2 else b"W",
            inode=0, size=0, latency_ns=120000, cpu_id=i % 8,
            dev=(8 << 20) | 1, ts=base_ts + i * 800,
            sector=i * 8, bio_size=4096, queue_time_ns=3000,
            cmd_flags=0, op_code=0, req_id=i,
        ))
    return out


def run_stream(tracer, stream, events):
    if stream == "fs":
        cb = tracer._print_event
    elif stream == "cache":
        cb = tracer._print_event_cache
    elif stream == "block":
        cb = tracer._print_event_block
    else:
        raise ValueError(stream)
    for ev in events:
        cb(0, ev, 0)


def main():
    ap = argparse.ArgumentParser(description="Profile the IO Tracer userspace hot path")
    ap.add_argument("-n", "--num-events", type=int, default=500_000,
                    help="number of synthetic events to push (default: 500000)")
    ap.add_argument("--stream", choices=["fs", "cache", "block"], default="fs",
                    help="which callback to profile (default: fs)")
    ap.add_argument("--no-compress", action="store_true",
                    help="disable writer flush/rotate/compress (isolate per-event cost)")
    ap.add_argument("--sort", default="cumulative",
                    choices=["cumulative", "tottime", "ncalls"],
                    help="pstats sort key (default: cumulative)")
    ap.add_argument("--top", type=int, default=25, help="rows of pstats to show")
    ap.add_argument("--dump", default=None, help="write raw .pstats to this path")
    ap.add_argument("--bench", action="store_true",
                    help="measure throughput WITHOUT cProfile overhead (accurate "
                         "events/s) and skip the per-function table")
    args = ap.parse_args()

    output_dir = tempfile.mkdtemp(prefix="iotrc_prof_")
    compress = not args.no_compress
    tracer = build_tracer(output_dir, compress)

    fm = tracer.flag_mapper
    if args.stream == "fs":
        events = make_fs_events(fm, args.num_events, tracer._self_pid)
        # Warm the inode cache so READ/WRITE resolve a path (mirrors OPEN).
        for ino, path in {
            100000: "/var/lib/app/data.db",
            100001: "/home/user/project/main.log",
            100002: "/usr/lib/x86_64-linux-gnu/libc.so.6",
            100003: "/tmp/scratch/cache.idx",
        }.items():
            tracer.path_resolver.inode_to_path[ino] = path
    elif args.stream == "cache":
        events = make_cache_events(args.num_events, tracer._self_pid)
    else:
        events = make_block_events(args.num_events, tracer._self_pid)

    print(f"Profiling stream={args.stream} events={args.num_events:,} "
          f"compress={'on' if compress else 'off'} output={output_dir}")

    # Everything below runs inside try/finally so the temp trace tree is always
    # removed — including the early return in --bench mode and any exception.
    try:
        pr = None
        if args.bench:
            # cProfile inflates per-call cost ~5-10x; for an accurate throughput
            # number, time the same workload with the profiler off.
            wall0 = time.perf_counter()
            run_stream(tracer, args.stream, events)
            wall1 = time.perf_counter()
        else:
            pr = cProfile.Profile()
            wall0 = time.perf_counter()
            pr.enable()
            run_stream(tracer, args.stream, events)
            pr.disable()
            wall1 = time.perf_counter()

        # Flush remaining buffers (counts the final flush + compress in the
        # timing summary below, but not inside the per-event cProfile window).
        try:
            tracer.writer.write_to_disk()
            tracer.writer.close_handles()
        except Exception:
            pass

        elapsed = wall1 - wall0
        rate = args.num_events / elapsed if elapsed else 0.0
        print()
        print(f"=== Summary ({args.stream}) ===")
        print(f"events processed : {args.num_events:,}")
        print(f"wall time        : {elapsed:.3f} s")
        print(f"throughput       : {rate:,.0f} events/s")
        print(f"per-event cost   : {elapsed / args.num_events * 1e6:.3f} us/event")
        if pr is None:
            print("(measured with cProfile OFF — throughput is representative)")
            return
        print("(measured with cProfile ON — throughput is depressed; use --bench "
              "for an accurate rate)")
        print()

        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).strip_dirs()
        sort_key = {"cumulative": "cumulative", "tottime": "tottime", "ncalls": "ncalls"}[args.sort]
        ps.sort_stats(sort_key).print_stats(args.top)
        print(s.getvalue())

        if args.dump:
            pstats.Stats(pr).dump_stats(args.dump)
            print(f"raw stats written to {args.dump}")
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
