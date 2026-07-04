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


def tracepoint_format(category, name):
    """Read a tracepoint format file from debugfs or tracefs (either mount)."""
    for base in ("/sys/kernel/debug/tracing", "/sys/kernel/tracing"):
        try:
            with open(f"{base}/events/{category}/{name}/format") as f:
                return f.read()
        except OSError:
            continue
    return ""


def build_cflags():
    """Mirror IOTracer._init_bpf so CI compiles with the real flags."""
    cflags = [
        "-Wno-duplicate-decl-specifier",
        "-Wno-macro-redefined",
        "-mllvm",
        "-bpf-stack-size=4096",
    ]
    if "cmd_flags" in tracepoint_format("block", "block_rq_complete"):
        cflags.append("-DHAS_CMD_FLAGS")
    return cflags


def network_cflags():
    """Mirror IOTracer._init_bpf's --network feature gates."""
    cflags = ["-DENABLE_NETWORK"]
    if " reason;" in tracepoint_format("skb", "kfree_skb"):
        cflags.append("-DHAS_SKB_DROP_REASON")
    if " state;" in tracepoint_format("tcp", "tcp_retransmit_skb"):
        cflags.append("-DHAS_TCP_RETRANSMIT_STATE")
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
        (b"__arm64_sys_mremap", [("kprobe", "__arm64_sys_mremap", "trace_mremap_entry_arm64"),
                                 ("kretprobe", "__arm64_sys_mremap", "trace_mremap_ret")]),
        (b"__x64_sys_openat", [("kprobe", "__x64_sys_openat", "trace_openat_entry_x64")]),
        (b"__x64_sys_io_uring_enter", [("kprobe", "__x64_sys_io_uring_enter", "trace_io_uring_enter_x64")]),
        (b"__arm64_sys_io_uring_enter", [("kprobe", "__arm64_sys_io_uring_enter", "trace_io_uring_enter_arm64")]),
        (b"iomap_dio_rw", [("kprobe", "iomap_dio_rw", "trace_dio_entry_iomap"),
                           ("kretprobe", "iomap_dio_rw", "trace_dio_return")]),
        (b"__blockdev_direct_IO", [("kprobe", "__blockdev_direct_IO", "trace_dio_entry_blockdev")]),
        # Cache-probe guard/symbol alignment: each folio/page handler must be
        # compiled in exactly when its attach symbol exists on the running
        # kernel. A mismatch attaches fine on the dev kernel and silently
        # drops the probe family elsewhere, so validate every pair here.
        (b"folio_mark_accessed", [("kprobe", "folio_mark_accessed", "trace_folio_mark_accessed")]),
        (b"mark_page_accessed", [("kprobe", "mark_page_accessed", "trace_hit")]),
        (b"filemap_add_folio", [("kprobe", "filemap_add_folio", "trace_filemap_add_folio")]),
        (b"add_to_page_cache_lru", [("kprobe", "add_to_page_cache_lru", "trace_miss")]),
        (b"__folio_mark_dirty", [("kprobe", "__folio_mark_dirty", "trace_folio_mark_dirty")]),
        (b"folio_clear_dirty_for_io", [("kprobe", "folio_clear_dirty_for_io", "trace_folio_clear_dirty_for_io")]),
        (b"folio_end_writeback", [("kprobe", "folio_end_writeback", "trace_folio_end_writeback")]),
        (b"filemap_remove_folio", [("kprobe", "filemap_remove_folio", "trace_filemap_remove_folio")]),
        (b"__filemap_remove_folio", [("kprobe", "__filemap_remove_folio", "trace_cache_drop_folio")]),
        (b"do_page_cache_ra", [("kprobe", "do_page_cache_ra", "trace_page_cache_ra")]),
        (b"__do_page_cache_readahead", [("kprobe", "__do_page_cache_readahead", "trace_do_page_cache_readahead")]),
        (b"page_cache_ra_order", [("kprobe", "page_cache_ra_order", "trace_page_cache_ra_order")]),
        (b"shrink_folio_list", [("kprobe", "shrink_folio_list", "trace_shrink_folio_list")]),
        (b"shrink_page_list", [("kprobe", "shrink_page_list", "trace_shrink_folio_list")]),
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

    # Clean up the default program before compiling the network-enabled variant
    # so the two BPF objects don't hold overlapping probes simultaneously.
    b.cleanup()

    # Opt-in network subset: compile + load with -DENABLE_NETWORK so the
    # connection/sockopt/drop probes get verifier coverage too. Their
    # TRACEPOINT_PROBE handlers auto-attach on load, so a successful BPF()
    # construction validates both compile and attach.
    net_cflags = build_cflags() + network_cflags()
    print(f"cflags (network): {net_cflags}")
    b_net = BPF(src_file=BPF_FILE.encode(), cflags=net_cflags)
    print("OK: prober.c compiled with ENABLE_NETWORK (verifier passed, "
          "network tracepoints auto-attached).")
    b_net.cleanup()

    print("SUCCESS: BPF compile, load, and VFS probe attach all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
