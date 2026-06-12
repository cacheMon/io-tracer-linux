#!/usr/bin/env python3
"""
BPF compile + verifier smoke test for prober.c.

Compiles the eBPF program exactly the way IOTracer does (same cflags),
loads every BPF function into the kernel (this runs the in-kernel verifier),
and attaches the VFS read/write entry+return probes to confirm they verify
and attach. Exits non-zero on any failure so CI fails loudly.

Must be run as root on a host with bcc + kernel headers/BTF available
(e.g. a GitHub-hosted ubuntu-latest runner).
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BPF_FILE = os.path.join(REPO_ROOT, "src", "tracer", "prober", "prober.c")


def build_cflags():
    """Mirror IOTracer._init_bpf so CI compiles with the real flags."""
    cflags = [
        "-Wno-duplicate-decl-specifier",
        "-Wno-macro-redefined",
        "-mllvm",
        "-bpf-stack-size=4096",
    ]
    tp_format = "/sys/kernel/debug/tracing/events/block/block_rq_complete/format"
    if os.path.exists(tp_format):
        with open(tp_format) as f:
            if "cmd_flags" in f.read():
                cflags.append("-DHAS_CMD_FLAGS")
    return cflags


def main():
    try:
        from bcc import BPF
    except ImportError as e:
        print(f"FAIL: bcc python module not importable: {e}", file=sys.stderr)
        return 1

    print(f"Kernel: {os.uname().release}")
    print(f"BPF source: {BPF_FILE}")
    cflags = build_cflags()
    print(f"cflags: {cflags}")

    # Constructing BPF() compiles the program and loads every function,
    # running the in-kernel verifier on each. It also auto-attaches the
    # kprobe__/tracepoint__ prefixed handlers.
    b = BPF(src_file=BPF_FILE.encode(), cflags=cflags)
    print("OK: prober.c compiled and all BPF programs loaded (verifier passed).")

    # Explicitly attach the VFS read/write entry+return probes added by this
    # work so their attachment is validated too.
    probes = [
        ("kprobe", "vfs_read", "trace_vfs_read"),
        ("kretprobe", "vfs_read", "trace_vfs_read_ret"),
        ("kprobe", "vfs_write", "trace_vfs_write"),
        ("kretprobe", "vfs_write", "trace_vfs_write_ret"),
        # fsync de-dup pair: the kretprobe clears the nested-call marker.
        ("kprobe", "vfs_fsync", "trace_vfs_fsync"),
        ("kretprobe", "vfs_fsync", "trace_vfs_fsync_ret"),
        ("kprobe", "vfs_fsync_range", "trace_vfs_fsync_range"),
    ]

    # Symbol-conditional probes. These validate that the pt_regs-unwrapping
    # *_x64 variants and the DIO direction entry probes were compiled in and
    # attach — a guard mismatch would otherwise pass CI (BPF() load succeeds
    # without them) and abort the tracer at startup instead.
    conditional_probes = [
        (b"__x64_sys_mremap", [("kprobe", "__x64_sys_mremap", "trace_mremap_entry_x64"),
                               ("kretprobe", "__x64_sys_mremap", "trace_mremap_ret")]),
        (b"__x64_sys_openat", [("kprobe", "__x64_sys_openat", "trace_openat_entry_x64")]),
        (b"__x64_sys_io_uring_enter", [("kprobe", "__x64_sys_io_uring_enter", "trace_io_uring_enter_x64")]),
        (b"iomap_dio_rw", [("kprobe", "iomap_dio_rw", "trace_dio_entry_iomap"),
                           ("kretprobe", "iomap_dio_rw", "trace_dio_return")]),
        (b"__blockdev_direct_IO", [("kprobe", "__blockdev_direct_IO", "trace_dio_entry_blockdev")]),
    ]
    for symbol, symbol_probes in conditional_probes:
        if BPF.get_kprobe_functions(symbol):
            probes.extend(symbol_probes)
        else:
            print(f"SKIP: {symbol.decode()} not present on this kernel")

    for kind, event, fn in probes:
        if kind == "kprobe":
            b.attach_kprobe(event=event, fn_name=fn)
        else:
            b.attach_kretprobe(event=event, fn_name=fn)
        print(f"OK: attached {kind} {event} -> {fn}")

    print("SUCCESS: BPF compile, load, and VFS probe attach all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
