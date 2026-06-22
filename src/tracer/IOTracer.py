#!/usr/bin/python3
"""
IOTracer - Main tracing class for Linux I/O syscall monitoring.

This module contains the IOTracer class which orchestrates all tracing
operations using eBPF/BPF technology. It captures:
- File system operations (VFS calls: read, write, open, close, etc.)
- Block device I/O operations
- Page cache events (hits, misses, dirty pages, etc.)

The tracer uses kernel probes (kprobes) to intercept I/O syscalls and
collects data in real-time, writing it to compressed CSV files.

Usage:
    tracer = IOTracer(output_dir="/path/to/output", bpf_file="path/to/prober.c")
    tracer.trace()
"""

import shutil
import signal
import os
import ctypes
import threading
import json
import platform
import socket
import struct
from bcc import BPF
import time
import sys
from bisect import bisect_right
from datetime import datetime

from . import schema
from .ObjectStorageManager import ObjectStorageManager
from ..utility.utils import capture_machine_id, format_csv_row, logger, anonymize_path, inet6_from_event, simple_hash, run_with_spinner
from .WriterManager import WriteManager
from .FlagMapper import FlagMapper
from .KernelProbeTracker import KernelProbeTracker
from .PollingThread import PollingThread
from .PathResolver import PathResolver
from .snappers.FilesystemSnapper import FilesystemSnapper
from .snappers.ProcessSnapper import ProcessSnapper
from .snappers.SystemSnapper import SystemSnapper


# VFS ops that never carry an I/O size; their `size` column is left empty per the
# schema ("empty for non-I/O ops"). Every other op keeps its numeric size,
# including a legitimate 0 (e.g. an EOF read or 0-byte write).
_NON_IO_SIZE_OPS = frozenset({
    "OPEN", "CLOSE", "GETATTR", "SETATTR", "CHDIR", "READDIR", "UNLINK",
    "SYNC", "RENAME", "MKDIR", "RMDIR", "LINK", "SYMLINK",
    "PROCESS_EXEC", "PROCESS_EXIT",
})


class IOTracer:
    """
    Main class for tracing Linux I/O operations.
    
    IOTracer initializes and manages the entire tracing pipeline, including:
    - BPF program compilation and kernel probe attachment
    - Event collection from perf buffers
    - Snapshot capture for filesystem and process state
    - Data writing and optional automatic upload
    
    Attributes:
        writer: WriteManager instance for handling data output
        fs_snapper: FilesystemSnapper for capturing filesystem state
        process_snapper: ProcessSnapper for capturing process information
        system_snapper: SystemSnapper for capturing system specifications
        flag_mapper: FlagMapper for decoding operation flags
        running: Boolean indicating if tracing is active
        verbose: Boolean enabling verbose output
        anonymous: Boolean enabling data anonymization
    """
    
    def __init__(
            self,
            output_dir:         str,
            bpf_file:           str,
            automatic_upload:   bool,
            developer_mode:     bool,
            version:            str,
            is_uncompressed:    bool = False,
            anonymous:          bool = False,
            page_cnt:           int = 8,
            verbose:            bool = False,
            duration:           int | None = None,
            cache_sample_rate:  int = 1,
            trace_bucket:       str | None = None,
            trace_cache:        bool = False,
            trace_network:      bool = False,
        ):
        """
        Initialize the IOTracer.
        
        Args:
            output_dir: Directory path for output files
            bpf_file: Path to the BPF C source file
            automatic_upload: Whether to automatically upload traces
            developer_mode: Enable developer mode with extra logging
            version: Application version string
            is_uncompressed: Whether to skip compression (default: False)
            anonymous: Whether to anonymize process/file names (default: False)
            page_cnt: Number of pages for perf buffer (default: 8)
            verbose: Enable verbose output (default: False)
            duration: Trace duration in seconds (default: None for indefinite)
            cache_sample_rate: Sample rate for cache events (default: 1 = no sampling)
            trace_cache: Attach page-cache probes and stream cache events
                (default: False — off to keep overhead minimal)
            trace_network: Compile/attach the low-overhead network probe subset
                (connection lifecycle, sockopt, drops) and stream their
                events (default: False — off to keep overhead minimal)

        Raises:
            SystemExit: If page count or duration is invalid
            SystemExit: If BPF initialization fails
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(output_dir, "linux_trace" ,capture_machine_id().upper() ,str(timestamp))

        temp_version = version if not developer_mode else f"vdev"
        if developer_mode:
            _W = "\033[1;33m"  # bold yellow
            _R = "\033[0m"     # reset
            _banner = (
                f"\n{_W}{'#' * 60}{_R}\n"
                f"{_W}{'#':1}{'':2}⚠   D E V E L O P E R   M O D E   A C T I V E   ⚠{'':2}{'#':>1}{_R}\n"
                f"{_W}{'#' * 60}{_R}\n"
                f"{_W}  › Trace data tagged [vdev] — NOT for production use.{_R}\n"
                f"{_W}  › Extra logs and internal checks are ON.{_R}\n"
                f"{_W}  › Make sure you know what you are doing.{_R}\n"
                f"{_W}{'#' * 60}{_R}\n"
            )
            print(_banner)
            confirm = input(f"{_W}Continue? [y/N]:{_R} ").strip().lower()
            if confirm != "y":
                print("Aborted.")
                raise SystemExit(0)
        osm_kwargs = {"version": temp_version}
        if trace_bucket is not None:
            osm_kwargs["trace_bucket"] = trace_bucket
        self.upload_manager     = ObjectStorageManager(**osm_kwargs)
        self.automatic_upload   = automatic_upload

        # Test connection for automatic upload
        if self.automatic_upload:
            connection = self.upload_manager.test_connection()
            if not connection:
                self.automatic_upload = False


        self.writer             = WriteManager(output_dir, self.upload_manager, automatic_upload)
        self.fs_snapper         = FilesystemSnapper(self.writer, anonymous)
        self.process_snapper    = ProcessSnapper(self.writer, anonymous)
        self.system_snapper     = SystemSnapper(self.writer)
        self.flag_mapper        = FlagMapper()
        self.running            = True
        # Shutdown is driven by _cleanup, which can be entered more than once —
        # the SIGINT/SIGTERM handler, a second signal, and the timed path all
        # call it. This non-reentrant lock makes it run exactly once; a
        # re-entrant or concurrent call returns immediately instead of flushing
        # and detaching probes twice on already-closed handles.
        self._cleanup_lock      = threading.Lock()
        self._cleanup_done      = False
        self._poll_thread       = None
        self.verbose            = verbose
        self.duration           = duration
        self.anonymous          = anonymous
        self.is_uncompressed    = is_uncompressed
        self.trace_cache        = trace_cache
        self.trace_network      = trace_network
        self.path_resolver      = PathResolver()
        self.mmap_regions       = {}
        self.cmdline_cache      = {}  # pid -> cmdline, populated on first successful read

        # Wall-clock conversion for kernel event timestamps. bpf_ktime_get_ns()
        # is CLOCK_MONOTONIC (ns since boot); adding this offset recovers
        # wall-clock time. Using the kernel's per-event timestamp instead of the
        # userspace receive time keeps rows correctly ordered in time across the
        # per-CPU perf buffers (which deliver in batches, not global order).
        # Integer-ns math avoids the float precision loss of subtracting two
        # large second-valued floats.
        self._mono_to_real_offset_ns = time.time_ns() - time.monotonic_ns()
        # The tracer (and its in-process snapshot/upload threads) read /proc,
        # write the trace files, and upload them — all of which is self-noise we
        # don't want in the trace. Filter events from our own pid.
        self._self_pid = os.getpid()
        # Per-stream dropped-event tallies (kernel perf-buffer overruns), folded
        # into the session manifest.
        self._lost_counts = {}
        self.version = version

        # Bounded-cache maintenance. The path resolver and cmdline caches are
        # only evicted on PROCESS_EXEC, so over a long-running trace they would
        # otherwise grow without bound. Maintenance runs from the perf-callback
        # (polling) thread — the only thread that mutates these caches — so it
        # never races with event processing.
        self._event_count           = 0
        self._maintenance_interval  = 50000  # events between cache sweeps
        self._cmdline_cache_max     = 100000  # hard cap on cmdline cache entries

        if cache_sample_rate > 1:
            self.writer.set_cache_sampling(cache_sample_rate)

        if page_cnt is None or page_cnt <= 0:
            logger("error", f"Invalid page count: {page_cnt}. Page count must be a positive integer.")
            sys.exit(1)
        self.page_cnt = page_cnt

        # Per-stream perf-buffer sizing (pages per CPU; a perf buffer requires a
        # power-of-two page count). A flat page_cnt=8 (32 KB/CPU) overflowed on
        # the high-volume page-cache and VFS streams — a short bursty workload
        # dropped ~64% of cache events and ~27% of fs events *in the kernel*
        # because the single poll thread could not drain the tiny buffers fast
        # enough. Give the hot streams much larger kernel buffers so they absorb
        # bursts and drain during lulls; keep the low-rate streams (block,
        # network) modest to bound memory. (page_cnt is rounded up to a power of
        # two so an odd --page-cnt override stays valid.)
        base = 1 << max(0, self.page_cnt - 1).bit_length()
        self._page_cnt_cache = max(base, 256)   # ~1 MB/CPU   — hottest stream
        self._page_cnt_fs    = max(base, 128)   # ~512 KB/CPU — VFS + io_uring
        self._page_cnt_block = max(base, 64)    # ~256 KB/CPU
        self._page_cnt_net   = max(base, 32)    # ~128 KB/CPU — low event rate

        if duration is not None and duration <= 0:
            logger("error", f"Invalid duration: {duration}. Duration must be a positive integer.")
            sys.exit(1)

        self.b: BPF
        self.probe_tracker: KernelProbeTracker

        try:
            def _init_bpf():
                cflags = ["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined", "-mllvm", "-bpf-stack-size=4096"]
                tp_format = "/sys/kernel/debug/tracing/events/block/block_rq_complete/format"
                if os.path.exists(tp_format):
                    with open(tp_format, "r") as f:
                        if "cmd_flags" in f.read():
                            cflags.append("-DHAS_CMD_FLAGS")
                # Compile the network probe subset only when requested. The
                # connection/sockopt/drop probes auto-attach when compiled,
                # so gating at compile time keeps overhead at zero when off.
                if self.trace_network:
                    cflags.append("-DENABLE_NETWORK")
                self.b = BPF(src_file=bpf_file.encode(), cflags=cflags)
                self.probe_tracker = KernelProbeTracker(self.b, developer_mode, trace_cache=self.trace_cache)

            run_with_spinner("Loading BPF program", _init_bpf)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            print("Your device are incompatible with this version of IO Tracer. Please notify us at io-tracer@googlegroups.com")
            sys.exit(1)

    def _should_filter_process(self, comm: str) -> bool:
        """Helper to filter out I/O unrelated system processes."""
        prefixes = ("swapper/", "ksoftirqd/", "irq/", "migration/", "stopper/")
        return comm.startswith(prefixes)

    def _ns_to_walltime(self, ts_ns):
        """Convert a kernel ``bpf_ktime_get_ns()`` (CLOCK_MONOTONIC) value to a
        wall-clock ``datetime``.

        Returns the userspace receive time when ``ts_ns`` is missing/zero, or if
        the value is out of ``datetime``'s representable range — a garbage
        timestamp must never raise out of a perf-buffer callback.
        """
        if not ts_ns:
            return datetime.today()
        try:
            return datetime.fromtimestamp((ts_ns + self._mono_to_real_offset_ns) / 1e9)
        except (OverflowError, OSError, ValueError):
            return datetime.today()

    def _event_walltime(self, event):
        """Wall-clock time for a perf event, from its kernel ``ts`` field.

        Using the kernel's per-event monotonic time (rather than the userspace
        receive time) yields correctly ordered timestamps across the per-CPU
        perf buffers. Falls back to receive time when the event carries no ts.
        """
        return self._ns_to_walltime(getattr(event, "ts", 0))

    def _print_event(self, cpu, data, size):        
        """
        Callback for processing file system VFS events from the perf buffer.
        
        This method is called for each VFS (Virtual File System) operation
        captured by the kernel probes.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        self._tick_maintenance()

        event = self.b["events"].event(data)
        # Drop the tracer's own I/O before any decode/timestamp work.
        if event.pid == self._self_pid:
            return
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")

        try:
            filename = event.filename.decode()
            if self.anonymous:
                filename = anonymize_path(filename)
            if op_name in ['MKDIR', 'RMDIR', 'CHDIR', 'READDIR'] and filename and not filename.endswith('/'):
                filename += '/'
        except UnicodeDecodeError:
            filename = ""
        
        timestamp = self._event_walltime(event)

        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"

        if self._should_filter_process(comm):
            return

        inode_val = event.inode if event.inode != 0 else ""
        
        # Empty only for non-I/O ops (schema: "empty for non-I/O ops"); I/O ops
        # keep their numeric size INCLUDING a legitimate 0 (EOF read, 0-byte
        # write, 0-range fsync). Gating on op type — not truthiness — avoids
        # blanking real 0-byte I/O.
        size_val = "" if op_name in _NON_IO_SIZE_OPS else event.size
        address_val = ""
        raw_address = event.address if hasattr(event, 'address') else 0
        if raw_address:
            address_val = f"0x{raw_address:x}"
        
        # Enhanced fields
        offset_val = event.offset if hasattr(event, 'offset') and event.offset != 0 else ""
        tid_val = event.tid if hasattr(event, 'tid') and event.tid != 0 else ""
        flags_val = self.flag_mapper.format_vfs_flags(op_name, event.flags)
        mmap_prot_val = ""
        mmap_flags_val = ""

        if op_name == "MMAP":
            flags_val = ""
            raw_mmap_prot = event.mmap_prot if hasattr(event, 'mmap_prot') else 0
            raw_mmap_flags = event.mmap_flags if hasattr(event, 'mmap_flags') else 0
            mmap_prot_val = self.flag_mapper.format_mmap_prot_flags(raw_mmap_prot)
            mmap_flags_val = self.flag_mapper.format_mmap_map_flags(raw_mmap_flags)
        
        # Path resolution strategy:
        # - OPEN events: bpf_d_path() in the kernel already wrote the full path
        #   into filename. Populate the inode cache so READ/WRITE on the same
        #   inode get the path for free. If bpf_d_path fell back to basename
        #   (no leading '/'), try fd-based userspace resolution as a backup.
        # - All other events: check the inode cache populated by OPEN events.
        if not self.anonymous and event.inode != 0:
            if op_name == 'OPEN':
                if filename and filename.startswith('/'):
                    # Kernel gave us the full path — just cache it
                    self.path_resolver.inode_to_path[event.inode] = filename
                else:
                    # bpf_d_path fell back to basename; try userspace fd resolution
                    fd = event.fd if hasattr(event, 'fd') and event.fd else 0
                    if fd:
                        filename = self.path_resolver.resolve_by_fd(
                            pid=event.pid, fd=fd, inode=event.inode, filename=filename
                        )
                    else:
                        filename = self.path_resolver.resolve_open_path(
                            pid=event.pid, inode=event.inode, filename=filename
                        )
                    # Last resort: if still relative (fd already closed / process
                    # gone), resolve the captured relative path against the
                    # openat dirfd or process cwd.
                    if filename and not filename.startswith('/'):
                        dirfd = event.dirfd if hasattr(event, 'dirfd') else self.path_resolver.AT_FDCWD
                        filename = self.path_resolver.resolve_relative(
                            pid=event.pid, dirfd=dirfd, relpath=filename, inode=event.inode
                        )
            else:
                cached = self.path_resolver.inode_to_path.get(event.inode)
                if cached:
                    filename = cached

        # Invariant: an OPEN filename is absolute or a clean basename, never an
        # unanchored relative path. If it is still relative here (inode==0 skipped
        # resolution above, or every resolver raced a closed fd/cwd), reduce it to
        # its basename. Anonymous mode already hashed the path at decode time.
        if op_name == 'OPEN' and not self.anonymous and filename and not filename.startswith('/'):
            filename = os.path.basename(filename) or filename

        if raw_address:
            if op_name == "MMAP":
                self._track_mmap_region(event.pid, raw_address, event.size, filename)
            elif op_name == "MUNMAP":
                resolved_filename = self._resolve_munmap_filename(event.pid, raw_address, event.size)
                if resolved_filename:
                    filename = resolved_filename

        # Resolve cmdline before any cache eviction so PROCESS_EXIT and
        # post-exit CLOSE events still get the cached value.
        cmdline = self._read_cmdline_cached(event.pid)

        # Handle vm lifecycle events that update the region cache only
        if op_name == "MREMAP":
            old_addr_val = event.old_addr if hasattr(event, 'old_addr') else 0
            old_size_val = event.old_size if hasattr(event, 'old_size') else 0
            resolved_filename = self._handle_mremap(
                event.pid, old_addr_val, old_size_val, raw_address, event.size
            )
            if resolved_filename:
                filename = resolved_filename
            old_addr_str = f"0x{old_addr_val:x}" if old_addr_val else ""
            if old_addr_str:
                address_val = f"{old_addr_str} -> {address_val}"
        elif op_name in ("PROCESS_EXEC", "PROCESS_EXIT"):
            if op_name == "PROCESS_EXEC":
                # execve() replaces the address space; evict stale mmap regions
                # AND the old cmdline (argv changes after exec).
                self._handle_process_exec(event.pid)
                if cmdline and not filename:
                    # Use argv[0] as the filename if eBPF didn't populate it
                    filename = cmdline.split(" ")[0]
            else:
                # EXIT: only clear mmap regions. Keep cmdline in cache so that
                # CLOSE events buffered after PROCESS_EXIT can still resolve it.
                self.mmap_regions.pop(event.pid, None)

        # Completion metadata — READ/WRITE carry the syscall return value, errno,
        # completed byte count, and duration (filled by the kretprobes).
        return_value = ""
        errno_val = ""
        bytes_completed = ""
        duration_ns = ""
        if op_name in ("READ", "WRITE", "SENDFILE"):
            ret = event.ret_val
            return_value = str(ret)
            if ret < 0:
                errno_val = self.flag_mapper.format_errno(-ret)
            else:
                bytes_completed = str(ret)
            duration_ns = str(event.latency_ns) if event.latency_ns else ""
        elif op_name in ("FSYNC", "FDATASYNC"):
            # Durability latency: entry->return duration filled by the fsync
            # kretprobe. No return value / byte count is captured for syncs.
            duration_ns = str(event.latency_ns) if event.latency_ns else ""

        # Provenance metadata — populated for READ/WRITE/OPEN.
        dev_val = self._format_dev(event.dev) if getattr(event, "dev", 0) else ""
        ppid_val = event.ppid if getattr(event, "ppid", 0) else ""
        container_id = event.cgroup_id if getattr(event, "cgroup_id", 0) else ""
        fs_type_val = (
            self.flag_mapper.format_fs_type(event.fs_magic)
            if getattr(event, "fs_magic", 0) else ""
        )

        # Aligned schema (v3): shared cross-OS prefix first, Linux-only extras
        # after, lowercase canonical operation name.
        output = format_csv_row(
            timestamp, op_name.lower(), event.pid, tid_val, comm, filename,
            size_val, offset_val, bytes_completed, inode_val, dev_val, flags_val,
            duration_ns, return_value, errno_val,
            mmap_prot_val, mmap_flags_val, address_val, cmdline,
            ppid_val, container_id, fs_type_val,
            getattr(event, "ts", 0)
        )
        self.writer.append_fs_log(output)

    @staticmethod
    def _format_dev(dev: int) -> str:
        """Decode a dev_t (super_block->s_dev) into 'major:minor'."""
        if not dev:
            return ""
        major = (dev >> 20) & 0xfff
        minor = dev & 0xfffff
        return f"{major}:{minor}"

    def _track_mmap_region(self, pid: int, start: int, length: int, filename: str) -> None:
        """Track file-backed mappings so later munmap events can recover filenames."""
        if not start or length <= 0:
            return

        end = start + length
        regions = self.mmap_regions.setdefault(pid, {})
        regions[start] = {
            "end": end,
            "filename": filename,
        }

    def _resolve_munmap_filename(self, pid: int, start: int, length: int) -> str:
        """Resolve munmap filename from the best matching tracked mmap region."""
        regions = self.mmap_regions.get(pid)
        if not regions:
            return ""

        match_start = self._find_region_start(regions, start)
        if match_start is None:
            return ""

        region = regions.get(match_start)
        if not region:
            return ""

        filename = region.get("filename", "")
        self._apply_munmap_to_region(pid, match_start, start, length)
        return filename

    def _find_region_start(self, regions: dict, address: int) -> int | None:
        """Find the tracked region that contains the given address."""
        if address in regions:
            return address

        starts = sorted(regions)
        index = bisect_right(starts, address) - 1
        if index < 0:
            return None

        candidate_start = starts[index]
        candidate = regions[candidate_start]
        if address < candidate["end"]:
            return candidate_start
        return None

    def _apply_munmap_to_region(self, pid: int, region_start: int, unmap_start: int, length: int) -> None:
        """Shrink, split, or remove a tracked mmap region after munmap."""
        regions = self.mmap_regions.get(pid)
        if not regions or length <= 0:
            return

        region = regions.get(region_start)
        if not region:
            return

        region_end = region["end"]
        unmap_end = unmap_start + length

        if unmap_end <= region_start or unmap_start >= region_end:
            return

        filename = region["filename"]
        del regions[region_start]

        if region_start < unmap_start:
            regions[region_start] = {
                "end": unmap_start,
                "filename": filename,
            }

        if unmap_end < region_end:
            regions[unmap_end] = {
                "end": region_end,
                "filename": filename,
            }

        if not regions:
            self.mmap_regions.pop(pid, None)

    def _handle_mremap(
        self, pid: int, old_addr: int, old_len: int, new_addr: int, new_len: int
    ) -> str:
        """
        Update the mmap_regions cache when an mremap() succeeds.

        Handles three cases:
        - Move: old_addr != new_addr → remove old region, insert new one
        - Resize in place: old_addr == new_addr → update region end
        - Unknown region: ignore silently (mapping predates the tracer)

        Returns:
            str: filename of the affected region, or "" if not found
        """
        regions = self.mmap_regions.get(pid)
        if not regions:
            return ""

        match_start = self._find_region_start(regions, old_addr)
        if match_start is None:
            return ""

        region = regions[match_start]
        filename = region.get("filename", "")

        if new_addr == old_addr:
            # Case 2 — resize in place
            region["end"] = new_addr + new_len
        else:
            # Case 1 — mapping moved to a new address
            del regions[match_start]
            regions[new_addr] = {
                "end": new_addr + new_len,
                "filename": filename,
            }

        if not regions:
            self.mmap_regions.pop(pid, None)

        return filename

    def _read_cmdline(self, pid: int, max_len: int = 512) -> str:
        """
        Read the command line of a process from /proc/<pid>/cmdline.

        /proc/<pid>/cmdline contains the argv array with each argument
        separated by a null byte. We replace null bytes with spaces to
        produce a human-readable command line string.

        Long command lines (e.g. shell glob expansions, fd listings) are
        truncated to `max_len` characters with a trailing "..." so CSV rows
        stay bounded in size.

        Returns:
            str: Space-joined argument string (≤ max_len chars), or "" if
                 the process has already exited or the file is unreadable.
        """
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            if not raw:
                return ""
            # argv elements are separated by \x00; strip trailing \x00 before joining
            result = raw.rstrip(b"\x00").replace(b"\x00", b" ").decode("utf-8", errors="replace")
            if len(result) > max_len:
                result = result[:max_len] + "..."
            return result
        except Exception:
            return ""

    def _read_cmdline_cached(self, pid: int) -> str:
        """
        Return the cmdline for a PID, using a cache to survive process exit.

        eBPF events for short-lived processes arrive in the userspace perf
        buffer *after* the process has already exited, making /proc/<pid>/cmdline
        unreadable. The first successful read is stored in self.cmdline_cache so
        that all subsequent events for the same PID can recover the cmdline even
        after the process is gone. The cache entry is evicted on PROCESS_EXIT.

        Returns:
            str: Cached or freshly-read cmdline, or "" if never successfully read.
        """
        cached = self.cmdline_cache.get(pid)
        if cached is not None:
            return cached
        result = self._read_cmdline(pid)
        # Cache even an empty result. A PID that yields no cmdline is either a
        # kernel thread (always empty) or an already-exited process (empty going
        # forward), so without this every event from such PIDs — which can be
        # very high-rate under load — would re-open /proc/<pid>/cmdline and fail
        # again. Stale entries after PID reuse are handled by the PROCESS_EXEC
        # eviction, which fires for the new process before its events.
        self.cmdline_cache[pid] = result
        return result

    def _tick_maintenance(self) -> None:
        """
        Advance the event counter and run cache maintenance when it is due.

        Called from every perf callback that runs on the polling thread and
        touches the long-lived caches (``_print_event``, ``_print_event_dual``,
        ``_print_event_io_uring``) so a workload dominated by any single event
        family — e.g. rename/link/symlink (dual) or async io_uring I/O — still
        triggers eviction instead of growing the caches unbounded.
        """
        self._event_count += 1
        if self._event_count % self._maintenance_interval == 0:
            self._run_cache_maintenance()

    def _run_cache_maintenance(self) -> None:
        """
        Bound the long-lived caches so an indefinite trace does not leak memory.

        Runs from the perf-callback (polling) thread, which is the only thread
        that mutates ``cmdline_cache`` and the path resolver caches, so no
        locking is required.

        - Delegates to ``PathResolver.cleanup_old_cache`` (otherwise never
          called), which prunes stale per-PID entries and caps ``inode_to_path``.
        - Caps ``cmdline_cache`` at ``_cmdline_cache_max`` entries. Entries are
          deliberately retained past process exit so that CLOSE/EXIT events
          buffered after the process is gone can still resolve a cmdline; when
          the cap is exceeded we drop the oldest half (dicts preserve insertion
          order), keeping the most recently seen PIDs.
        """
        try:
            self.path_resolver.cleanup_old_cache()
        except Exception as e:
            if self.verbose:
                logger("warning", f"Path resolver cache cleanup failed: {e}")

        if len(self.cmdline_cache) > self._cmdline_cache_max:
            items = list(self.cmdline_cache.items())
            self.cmdline_cache = dict(items[len(items) // 2:])

    def _handle_process_exec(self, pid: int) -> None:
        """
        Clear the mmap_regions and cmdline caches for a PID on exec.

        execve() replaces the entire virtual address space, so all tracked
        mappings are immediately stale. The cmdline also changes (new argv),
        so flush the cache entry so the next read picks up the new cmdline.
        """
        self.mmap_regions.pop(pid, None)
        self.cmdline_cache.pop(pid, None)

    def _handle_process_exit(self, pid: int) -> None:
        """
        Clear the mmap_regions cache for a PID on exit.

        mmap regions are released, but the cmdline cache is intentionally
        kept so that CLOSE events arriving in the perf buffer after
        PROCESS_EXIT can still resolve the cmdline. The cache entry will be
        evicted if the PID is reused and a PROCESS_EXEC arrives for it.
        """
        self.mmap_regions.pop(pid, None)

    def _print_event_dual(self, cpu, data, size):
        """
        Callback for processing dual-path filesystem events from the perf buffer.
        
        This method handles operations with two paths (source and destination),
        such as rename and link operations.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        self._tick_maintenance()

        event = self.b["events_dual"].event(data)
        # Drop the tracer's own I/O before any decode/timestamp work.
        if event.pid == self._self_pid:
            return
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename_old = event.filename_old.decode()
            filename_new = event.filename_new.decode()
            if self.anonymous:
                filename_old = anonymize_path(filename_old)
                filename_new = anonymize_path(filename_new)
        except UnicodeDecodeError:
            filename_old = ""
            filename_new = ""
        
        timestamp = self._event_walltime(event)

        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"

        if self._should_filter_process(comm):
            return

        inode_old = event.inode_old if event.inode_old != 0 else ""
        inode_new = event.inode_new if event.inode_new != 0 else ""
        
        # Format as "old -> new" for the filename column
        dual_filename = f"{filename_old} -> {filename_new}"
        
        # Use inode_old for the inode column
        inode_val = f"{inode_old}" if inode_old else ""
        
        flags_val = self.flag_mapper.format_vfs_flags(op_name, event.flags)
        cmdline = self._read_cmdline_cached(event.pid)

        # Emit the same aligned fs schema as _print_event so the shared fs log
        # stays a well-formed CSV. Dual-path ops (RENAME/LINK/SYMLINK) do not
        # carry size/offset/tid/mmap/address or the READ/WRITE/OPEN completion
        # and provenance fields, so those columns are empty.
        output = format_csv_row(
            timestamp, op_name.lower(), event.pid, "", comm, dual_filename,
            "", "", "", inode_val, "", flags_val,   # size,offset,bytes_completed,inode,device,flags
            "", "", "",                              # duration_ns, return_value, errno
            "", "", "", cmdline,                     # mmap_prot, mmap_flags, address, cmdline
            "", "", "",                              # ppid, container_id, fs_type
            getattr(event, "ts", 0)                  # mono_ns
        )
        self.writer.append_fs_log(output)

    def _print_event_cache(self, cpu, data, size):
        """
        Callback for processing page cache events from the perf buffer.
        
        Captures cache hits, misses, dirty pages, writebacks, evictions, etc.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["cache_events"].event(data)
        pid = event.pid
        if pid == self._self_pid:
            return
        timestamp = self._event_walltime(event)
        comm = event.comm.decode('utf-8', errors='replace')

        if self._should_filter_process(comm):
            return
        
        event_types = {
            0: "HIT",
            1: "MISS",
            2: "DIRTY",
            3: "WRITEBACK_START",
            4: "WRITEBACK_END",
            5: "EVICT",
            6: "INVALIDATE",
            7: "DROP",
            8: "READAHEAD",
            9: "RECLAIM"
        }
        event_name = event_types.get(event.type, "UNKNOWN")
        inode = event.inode if event.inode != 0 else ""
        index = event.index if event.index != 0 else ""
        
        # Cache event metadata
        size = event.size if hasattr(event, 'size') else ""
        cpu_id = event.cpu_id if hasattr(event, 'cpu_id') else ""
        dev_id = event.dev_id if hasattr(event, 'dev_id') else ""
        count = event.count if hasattr(event, 'count') else ""

        output = format_csv_row(timestamp, pid, comm, event_name, inode, index, size, cpu_id, dev_id, count, getattr(event, "ts", 0))

        self.writer.append_cache_log(output)

    def _print_event_conn(self, cpu, data, size):
        """
        Callback for connection-lifecycle events (low-overhead network subset).

        Captures socket creation, bind, listen, accept, connect, shutdown, close.
        """
        e = self.b["net_conn_events"].event(data)
        if e.pid == self._self_pid:
            return
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        if self._should_filter_process(comm):
            return

        timestamp = self._ns_to_walltime(getattr(e, "ts_ns", 0))
        event_type = FlagMapper.format_conn_event(e.event_type)
        domain = FlagMapper.format_domain(e.domain) if e.domain else ""
        sock_type = FlagMapper.format_sock_type(e.sock_type) if e.sock_type else ""
        ipver = str(e.ipver) if e.ipver else ""

        if e.ipver == 4:
            # saddr_v4/daddr_v4 hold the raw network-order bytes from the kernel;
            # ctypes already read them with native endianness, so pack back with
            # native "I" (not "!I") to reproduce the original bytes for inet_ntop.
            local_addr = socket.inet_ntop(socket.AF_INET, struct.pack("I", e.saddr_v4)) if e.saddr_v4 else ""
            remote_addr = socket.inet_ntop(socket.AF_INET, struct.pack("I", e.daddr_v4)) if e.daddr_v4 else ""
        elif e.ipver == 6:
            local_addr = inet6_from_event(e.saddr_v6) if e.saddr_v6 else ""
            remote_addr = inet6_from_event(e.daddr_v6) if e.daddr_v6 else ""
        else:
            local_addr = remote_addr = ""

        output = format_csv_row(
            timestamp,
            event_type,
            str(e.pid),
            str(e.tid),
            comm,
            domain,
            sock_type,
            ipver,
            local_addr,
            remote_addr,
            str(e.sport) if e.sport else "",
            str(e.dport) if e.dport else "",
            str(e.fd) if e.fd else "",
            str(e.backlog) if e.backlog else "",
            FlagMapper.format_shutdown_how(e.shutdown_how) if e.shutdown_how else "",
            str(e.latency_ns) if e.latency_ns else "",
            str(e.ret_val),
            getattr(e, "ts_ns", 0),
        )
        self.writer.append_conn_log(output)

    def _print_event_sockopt(self, cpu, data, size):
        """
        Callback for socket-option events (setsockopt/getsockopt).
        """
        e = self.b["net_sockopt_events"].event(data)
        if e.pid == self._self_pid:
            return
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        if self._should_filter_process(comm):
            return

        timestamp = self._ns_to_walltime(getattr(e, "ts_ns", 0))
        output = format_csv_row(
            timestamp,
            FlagMapper.format_sockopt_event(e.event_type),
            str(e.pid),
            comm,
            str(e.fd),
            FlagMapper.sockopt_level_map.get(e.level, str(e.level)),
            FlagMapper.format_sockopt(e.level, e.optname),
            str(e.optval),
            str(e.ret_val),
            getattr(e, "ts_ns", 0),
        )
        self.writer.append_sockopt_log(output)

    def _print_event_drop(self, cpu, data, size):
        """
        Callback for network drop/retransmission events.
        """
        e = self.b["net_drop_events"].event(data)
        if e.pid == self._self_pid:
            return
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        if self._should_filter_process(comm):
            return

        timestamp = self._ns_to_walltime(getattr(e, "ts_ns", 0))
        proto = FlagMapper.format_proto(e.proto) if e.proto else ""
        ipver = str(e.ipver) if e.ipver else ""

        if e.ipver == 4:
            # Native "I" pack (see _print_event_conn) reproduces the network-order
            # bytes ctypes read from the kernel; "!I" would reverse them.
            s_addr = socket.inet_ntop(socket.AF_INET, struct.pack("I", e.saddr_v4)) if e.saddr_v4 else ""
            d_addr = socket.inet_ntop(socket.AF_INET, struct.pack("I", e.daddr_v4)) if e.daddr_v4 else ""
        elif e.ipver == 6:
            s_addr = inet6_from_event(e.saddr_v6) if e.saddr_v6 else ""
            d_addr = inet6_from_event(e.daddr_v6) if e.daddr_v6 else ""
        else:
            s_addr = d_addr = ""

        output = format_csv_row(
            timestamp,
            FlagMapper.format_drop_event(e.event_type),
            str(e.pid),
            comm,
            proto,
            ipver,
            s_addr,
            d_addr,
            str(e.sport) if e.sport else "",
            str(e.dport) if e.dport else "",
            str(e.skb_len) if e.skb_len else "0",
            str(e.drop_reason) if e.drop_reason else "0",
            FlagMapper.format_tcp_state(e.state) if e.state else "",
            getattr(e, "ts_ns", 0),
        )
        self.writer.append_drop_log(output)

    def _print_event_block(self, cpu, data, size):
        """
        Callback for processing block device I/O events from the perf buffer.
        
        Captures block-level operations including sector locations, sizes,
        and latency information.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["bl_events"].event(data)

        pid = event.pid
        if pid == self._self_pid:
            return
        timestamp = self._event_walltime(event)
        tid = event.tid
        comm = event.comm.decode('utf-8', errors='replace')

        if self._should_filter_process(comm):
            return
            
        sector = event.sector
        ops_str = event.op.decode('utf-8', errors='replace')
        ops_str = self.flag_mapper.format_block_ops(ops_str)
        # Aligned schema (v3): the base op goes in ``operation`` and the rwbs
        # sub-flags (sync|meta|ahead|...) move to the dedicated ``flags`` column.
        _op_parts = ops_str.split("|")
        op_base = _op_parts[0]
        op_flags = "|".join(_op_parts[1:])
        latency_ns = event.latency_ns
        latency_ms = latency_ns / 1_000_000.0
        cpu_id = event.cpu_id
        ppid = event.ppid
        bio_size = event.bio_size
        
        # Queue time (new field)
        queue_time_ns = event.queue_time_ns if hasattr(event, 'queue_time_ns') else 0
        queue_time_ms = queue_time_ns / 1_000_000.0 if queue_time_ns else ""
        
        # Decode device number (dev_t) into major:minor for partition identification
        # dev_t encoding: major in bits 8-19, minor in bits 0-19 (on most modern kernels)
        dev = event.dev
        major = (dev >> 20) & 0xfff if dev > 0 else 0
        minor = dev & 0xfffff if dev > 0 else 0
        dev_str = f"{major}:{minor}"
        
        # Decode REQ_* command flags (REQ_SYNC, REQ_META, REQ_FUA, etc.)
        cmd_flags = event.cmd_flags if hasattr(event, 'cmd_flags') else 0
        cmd_flags_str = self.flag_mapper.decode_block_req_flags(cmd_flags) if cmd_flags else ""
        
        # Decode raw operation code (REQ_OP_READ, REQ_OP_WRITE, etc.)
        # Note: op_code is 0 on kernel 5.17+ where cmd_flags is unavailable - don't decode it
        op_code = event.op_code if hasattr(event, 'op_code') else 0
        op_code_str = self.flag_mapper.decode_block_op_code(op_code) if (op_code is not None and op_code != 0) else ""

        # Monotonic per-request id (disambiguates repeated I/O to the same sector)
        req_id = event.req_id if hasattr(event, 'req_id') else ""

        output = format_csv_row(timestamp, op_base, pid, tid, comm, sector, bio_size, latency_ms, dev_str, op_flags, cpu_id, ppid, queue_time_ms, cmd_flags_str, op_code_str, req_id, getattr(event, "ts", 0))


        if sector == 0 and bio_size == 0:
            if self.verbose:
                print("="*50)
                print("Warning: LBA 0 detected in block trace")
                print(output)
                print("="*50)
        self.writer.append_block_log(output)

    def _print_event_pagefault(self, cpu, data, size):
        """
        Callback for processing page fault events from the perf buffer.
        
        Captures mmap I/O patterns by tracking file-backed page faults.
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        event = self.b["pagefault_events"].event(data)
        pid = event.pid
        if pid == self._self_pid:
            return
        timestamp = self._event_walltime(event)
        tid = event.tid
        comm = event.comm.decode('utf-8', errors='replace')

        if self._should_filter_process(comm):
            return
            
        address = hex(event.address) if event.address else ""
        inode = event.inode if event.inode != 0 else ""
        offset = event.offset if event.offset != 0 else ""
        fault_type = "WRITE" if event.fault_type == 1 else "READ"
        major = "MAJOR" if event.major else "MINOR"
        dev_id = event.dev_id if hasattr(event, 'dev_id') and event.dev_id != 0 else ""
        
        output = format_csv_row(timestamp, pid, tid, comm, fault_type, major, inode, offset, address, dev_id, getattr(event, "ts", 0))
        self.writer.append_pagefault_log(output)

    def _print_event_io_uring(self, cpu, data, size):
        """
        Callback for io_uring perf events.

        The standalone io_uring trace stream has been removed. io_uring file
        activity is surfaced by mirroring completed READ/WRITE operations into
        the fs/VFS trace (they call ->read_iter/->write_iter directly, bypass
        vfs_read/vfs_write, and would otherwise be invisible). Other io_uring
        events (submit lifecycle, network/poll ops) are no longer recorded.

        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        self._tick_maintenance()

        e = self.b["io_uring_events"].event(data)

        # Only completed ops (event_type == 2) carry a result/latency and feed
        # the fs mirror; nothing else needs recording now that the separate
        # io_uring stream is gone.
        if e.event_type != 2:
            return

        # Use the kernel event time (io_uring's struct names it timestamp_ns) so
        # these mirrored rows share the same clock as the syscall-origin fs rows
        # they interleave with in the fs trace.
        ts = self._ns_to_walltime(getattr(e, "timestamp_ns", 0))
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")

        if self._should_filter_process(comm):
            return

        # File correlation — the prep probe records the backing file's inode,
        # device and filesystem. Resolve the path from the inode→path cache
        # (same strategy as VFS events) so mirrored io_uring I/O carries the
        # same file identity as the fs trace.
        dev_val = self._format_dev(e.dev) if getattr(e, "dev", 0) else ""
        fs_type_val = (
            self.flag_mapper.format_fs_type(e.fs_magic)
            if getattr(e, "fs_magic", 0) else ""
        )
        filename = ""
        if getattr(e, "inode", 0):
            cached = self.path_resolver.inode_to_path.get(e.inode)
            if cached:
                filename = cached
            if self.anonymous and filename:
                filename = anonymize_path(filename)

        # Mirror completed file READ/WRITE into the main fs/VFS trace stream.
        self._mirror_io_uring_to_fs(e, comm, filename, ts, dev_val, fs_type_val)


    def _mirror_io_uring_to_fs(self, e, comm, filename, ts, dev_val, fs_type_val):
        """
        Emit an fs/VFS-shaped row for a completed io_uring file READ/WRITE.

        io_uring read/write operations call ``->read_iter``/``->write_iter``
        directly and never pass through ``vfs_read``/``vfs_write``, so they are
        invisible to the VFS probes. To make async I/O visible alongside
        syscall I/O, this mirrors COMPLETE events for the read/write opcode
        families into the fs log using the same 22-column schema as
        ``_print_event``.

        fsync is intentionally not mirrored: io_uring FSYNC calls ``vfs_fsync``
        internally and is therefore already captured by the VFS fsync probe;
        mirroring it would double-count.

        Args:
            e: The io_uring perf event.
            comm: Decoded process name.
            filename: Resolved file path (may be empty).
            ts: Event datetime (matches the fs-log timestamp format).
            dev_val: Pre-formatted ``major:minor`` device string.
            fs_type_val: Pre-formatted filesystem name.
        """
        # IORING_OP_* read/write opcode families → unified fs operation name.
        op_map = {
            1: "READ",   # READV
            4: "READ",   # READ_FIXED
            22: "READ",  # READ
            2: "WRITE",  # WRITEV
            5: "WRITE",  # WRITE_FIXED
            23: "WRITE", # WRITE
        }
        op_name = op_map.get(e.opcode)
        if not op_name or not getattr(e, "inode", 0):
            return

        # On kernel >= 6.0 the completion result is not available to the kprobe
        # (io_req_complete_post no longer passes it as an argument), so the C
        # side leaves result unset and flags it via result_valid. Emit empty
        # return_value/bytes_completed in that case rather than a misleading 0.
        return_value = ""
        errno_val = ""
        bytes_completed = ""
        if getattr(e, "result_valid", 0):
            ret = e.result
            return_value = str(ret)
            if ret < 0:
                errno_val = self.flag_mapper.format_errno(-ret)
            else:
                bytes_completed = str(ret)
        duration_ns = str(e.latency_ns) if e.latency_ns else ""

        offset_val = e.offset if e.offset else ""
        tid_val = e.tid if e.tid else ""
        size_val = e.len if e.len else 0
        # io_uring rows carry the SQE flags (FIXED_FILE|ASYNC|IO_LINK…) in the
        # generic flags column in place of the open-file O_* flags, which are
        # not available on the io_uring path.
        flags_val = self.flag_mapper.format_io_uring_sqe_flags(e.sqe_flags)
        cmdline = self._read_cmdline_cached(e.pid)

        output = format_csv_row(
            ts, op_name.lower(), e.pid, tid_val, comm, filename,
            size_val, offset_val, bytes_completed, e.inode, dev_val, flags_val,
            duration_ns, return_value, errno_val,
            "", "", "", cmdline,            # mmap_prot, mmap_flags, address, cmdline
            "", "", fs_type_val,            # ppid, container_id, fs_type
            getattr(e, "timestamp_ns", 0)   # mono_ns
        )
        self.writer.append_fs_log(output)

    def _cleanup(self, signum, frame):
        # Run exactly once. _cleanup is reached from the SIGINT/SIGTERM handler,
        # a possible second signal (double Ctrl-C, or SIGINT then SIGTERM), and
        # the timed path's direct call — a non-blocking acquire makes every
        # entry after the first return immediately, so we never detach probes or
        # flush+close handles twice.
        if not self._cleanup_lock.acquire(blocking=False):
            return
        try:
            if self._cleanup_done:
                return
            self._cleanup_done = True
            self.running = False

            # Stop and JOIN the poll thread before touching handles. Previously
            # cleanup detached probes and closed the writer handles while the
            # poll thread was still running (polling_active was only cleared
            # later, in trace()'s finally), so a perf-buffer callback could write
            # to a handle being closed. Joining first guarantees no callback runs
            # during the flush/close below.
            if self.polling_thread is not None:
                self.polling_thread.polling_active = False
            if self._poll_thread is not None:
                self._poll_thread.join(timeout=2.0)

            self.probe_tracker.detach_kprobes()

            def _flush():
                self.fs_snapper.stop_snapper()
                self.process_snapper.stop_snapper()
                self.writer.write_to_disk()
                self.writer.close_handles()

            run_with_spinner("Flushing trace data", _flush)
        finally:
            self._cleanup_lock.release()

    def _block_stats(self, collapse_zero: bool = True):
        """Read the per-CPU ``block_stats`` map → {issued, completed, missed, stale}.

        Returns an empty dict if the map is unavailable, or — when
        ``collapse_zero`` is True (the default) — if every counter is zero.
        Pass ``collapse_zero=False`` to tell "no block I/O happened" (all-zero
        but map present) apart from "map unavailable". ``missed`` counts
        completions with no tracked issue ctx (LRU-evicted or pre-trace);
        ``stale`` counts completions dropped because the matched issue ctx had an
        implausible device latency ((dev, sector) key reused across a gap).
        """
        try:
            stats = self.b["block_stats"]
            out = {
                "issued":    int(sum(stats[ctypes.c_int(0)])),
                "completed": int(sum(stats[ctypes.c_int(1)])),
                "missed":    int(sum(stats[ctypes.c_int(2)])),
                "stale":     int(sum(stats[ctypes.c_int(3)])),
            }
        except Exception:
            return {}
        if collapse_zero and not any(out.values()):
            return {}
        return out

    def _log_block_diagnostics(self):
        """Log a summary of block-tracing health from ``block_stats``.

        Reads the map without zero-collapsing so the "zero physical block I/O"
        case is reported explicitly rather than silently skipped: an absent
        ``ds/`` stream is expected on short or cache-served runs, and saying so
        keeps it from looking like block tracing failed.

        For runs that did produce block I/O, completions with no matching issue
        ctx (``missed``) split into two kinds with different remedies:

        * **structural** — completions whose issue was never seen by the trace
          (in-flight before tracing started, or via a path that does not fire
          ``block_rq_issue``). Bounded by ``total_completions - issued`` and
          irreducible by map sizing.
        * **evictable** — the remainder: an issue ctx *was* recorded but was lost
          before its completion, via LRU eviction under load or ``(dev,sector)``
          key overwrite by a concurrent in-flight request. A larger
          ``block_start_times`` map reduces the eviction part.

        Reporting the split avoids blaming all misses on eviction (the previous
        behavior), which over-stated how much a bigger map can recover. A high
        miss rate means the issue map was evicted under load — the likely
        explanation if block events appear to stop before a long trace ends.
        """
        s = self._block_stats(collapse_zero=False)
        if not s:
            # Map genuinely unavailable (e.g. block tracepoints never loaded).
            return
        if not any(s.values()):
            logger("info",
                   "Block diagnostics: 0 block I/O events captured, so no ds/ "
                   "stream was written. This is expected on short or cache-served "
                   "runs — reads are served from the page cache and dirty-page "
                   "writeback may not have flushed, so no physical block I/O "
                   "reaches the device. The ds/ stream only appears once real "
                   "device I/O occurs (cache misses, fsync, writeback, direct I/O).")
            return
        stale = s.get("stale", 0)
        missed = s["missed"]
        total_completions = s["completed"] + missed + stale
        miss_pct = (missed / total_completions * 100) if total_completions else 0.0
        # Excess completions over issues had no recorded issue at all (structural,
        # unfixable by sizing); the rest were recorded then lost (evictable).
        structural = max(0, total_completions - s["issued"])
        structural = min(structural, missed)
        evictable = missed - structural
        logger("info",
               f"Block diagnostics: {s['issued']} issued, {s['completed']} completed, "
               f"{missed} completions without a tracked issue "
               f"({miss_pct:.1f}% of completions) — {structural} structural "
               f"(issue never seen; pre-trace or un-issued path) and {evictable} "
               f"evictable (issue lost to LRU eviction or (dev,sector) key reuse; "
               f"reducible with a larger issue map). {stale} dropped as stale "
               f"((dev,sector) key reuse).")

    def _attached_probes(self):
        """Sorted list of kernel functions the tracer has probes attached to."""
        try:
            events = ([e for e, _ in self.probe_tracker.kprobes] +
                      [e for e, _ in self.probe_tracker.kretprobes])
            return sorted(set(events))
        except Exception:
            return []

    def _write_manifest(self, started_at, stopped_at=None):
        """Write the per-session ``manifest.json`` (schema + clock + versions +
        session window + diagnostics). Written once when tracing starts and
        rewritten at shutdown with the stop time and final diagnostics.
        """
        manifest = schema.schema_for_manifest()
        duration = (stopped_at - started_at).total_seconds() if stopped_at else None
        manifest.update({
            "tracer": {"version": self.version},
            "machine_id": capture_machine_id(),
            "host": {
                "platform": platform.platform(),
                "kernel": platform.release(),
                "python": platform.python_version(),
            },
            "clock": {
                "wall_clock": "CLOCK_REALTIME",
                "mono_clock": "CLOCK_MONOTONIC",
                "mono_to_real_offset_ns": self._mono_to_real_offset_ns,
                "note": ("mono_ns is the common cross-stream correlation clock "
                         "(CLOCK_MONOTONIC ns). Add mono_to_real_offset_ns to it "
                         "to recover wall-clock nanoseconds."),
            },
            "session": {
                "started_at": started_at.isoformat(),
                "stopped_at": stopped_at.isoformat() if stopped_at else None,
                "duration_seconds": duration,
            },
            "diagnostics": {
                "attached_probes": self._attached_probes(),
                "lost_events": dict(self._lost_counts),
                "rows_written": dict(self.writer.rows_written),
                "write_dropped": dict(getattr(self.writer, "write_dropped", {})),
                "block": self._block_stats(),
            },
        })
        try:
            path = os.path.join(self.writer.output_dir, "manifest.json")
            with open(path, "w") as f:
                json.dump(manifest, f, indent=2)
        except OSError as e:
            logger("warning", f"Could not write manifest.json: {e}")

    def _make_lost_cb(self, label):
        """Build a per-buffer lost-event callback that tallies drops by stream
        label (for the session manifest) and warns when verbose."""
        def _cb(lost):
            if lost > 0:
                self._lost_counts[label] = self._lost_counts.get(label, 0) + lost
                if self.verbose:
                    logger("warning", f"Lost {lost} {label} events in kernel buffer")
        return _cb

    def trace(self):
        """
        Main method to start tracing operations.
        
        This method:
        1. Attaches all kernel probes
        2. Starts the upload worker if enabled
        3. Captures initial system/process/filesystem snapshots
        4. Opens perf buffers for all event types
        5. Runs the polling loop until duration expires or interrupted
        
        The trace runs indefinitely if no duration is specified,
        or for the specified number of seconds otherwise.
        """
        run_with_spinner("Attaching kernel probes", self.probe_tracker.attach_probes)
        if self.automatic_upload:
            self.upload_manager.start_worker()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        logger("info", "IO Tracer is running")
        logger("info", "Press Ctrl+C to exit")
        
        # Capture initial snapshots
        self.system_snapper.capture_spec_snapshot()
        self.fs_snapper.run()
        self.process_snapper.run()

        if self.writer.cache_sample_rate > 1:
            logger("info", f"Cache sampling enabled: 1:{self.writer.cache_sample_rate}")

        # Open perf buffers for each event type
        self.b["events"].open_perf_buffer(
            self._print_event,
            page_cnt=self._page_cnt_fs,
            lost_cb=self._make_lost_cb("fs")
        )

        self.b["events_dual"].open_perf_buffer(
            self._print_event_dual,
            page_cnt=self._page_cnt_fs,
            lost_cb=self._make_lost_cb("fs")
        )

        self.b["bl_events"].open_perf_buffer(
            self._print_event_block,
            page_cnt=self._page_cnt_block,
            lost_cb=self._make_lost_cb("block")
        )

        # Page-cache events are opt-in (--cache). The probes are only attached
        # when enabled, so this buffer otherwise has no producer; opening it only
        # when enabled avoids an idle reader.
        if self.trace_cache:
            self.b["cache_events"].open_perf_buffer(
                self._print_event_cache,
                page_cnt=self._page_cnt_cache,
                lost_cb=self._make_lost_cb("cache")
            )

        # Network events are opt-in (--network). The probes are compiled and the
        # perf buffers only exist when -DENABLE_NETWORK was passed, so guard both
        # the flag and the buffer lookup.
        if self.trace_network:
            for buf_name, callback, stream in (
                ("net_conn_events", self._print_event_conn, "nw_conn"),
                ("net_sockopt_events", self._print_event_sockopt, "nw_sockopt"),
                ("net_drop_events", self._print_event_drop, "nw_drop"),
            ):
                try:
                    self.b[buf_name].open_perf_buffer(
                        callback,
                        page_cnt=self._page_cnt_net,
                        lost_cb=self._make_lost_cb(stream)
                    )
                except KeyError:
                    if self.verbose:
                        logger("warning", f"{buf_name} buffer not available")

        # Page fault events for mmap I/O tracking
        # try:
        #     self.b["pagefault_events"].open_perf_buffer(
        #         self._print_event_pagefault,
        #         page_cnt=self.page_cnt,
        #         lost_cb=self._make_lost_cb("pagefault")
        #     )
        # except KeyError:
        #     if self.verbose:
        #         logger("warning", "pagefault_events buffer not available")

        # io_uring events for async I/O tracking
        try:
            self.b["io_uring_events"].open_perf_buffer(
                self._print_event_io_uring,
                page_cnt=self._page_cnt_fs,
                lost_cb=self._make_lost_cb("fs")
            )
        except KeyError:
            if self.verbose:
                logger("warning", "io_uring_events buffer not available")

        start = time.time()
        # Write the session manifest up front so a self-describing schema exists
        # even if the run is killed; it is rewritten at shutdown with the stop
        # time and final diagnostics.
        self._session_started_at = datetime.now()
        self._write_manifest(self._session_started_at)
        if self.duration is not None:
            duration_target = self.duration
            end_time = start + duration_target
            logger("info", f"Tracing for {duration_target} seconds...")
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")

        # Start the polling thread for perf buffer. Keep the Thread handle so
        # _cleanup can join it before flushing/closing handles (otherwise a
        # callback could still write to a handle being torn down).
        self.polling_thread = PollingThread(self.b, True)
        self._poll_thread = self.polling_thread.create_thread()

        try:
            if self.duration is not None:
                remaining = duration_target # type: ignore
                while remaining > 0 and self.running:
                    sleep_time = min(0.1, remaining)
                    time.sleep(sleep_time)

                    current = time.time()
                    remaining = end_time - current # type: ignore

                    if self.verbose and int(current) % 10 == 0 and int(current) > int(current - sleep_time):
                        elapsed = current - start
                        logger("info", f"Progress: {elapsed:.1f}s/{duration_target}s") # type: ignore
                        
                self._cleanup(None, None)
            else:
                # Run indefinitely until Ctrl+C
                while self.running:
                    time.sleep(0.1)

                    if self.verbose:
                        current = time.time()
                        if int(current) % 30 == 0:  # Every 30 seconds
                            elapsed = current - start
                            logger("info", f"Runtime: {elapsed:.1f}s")
                            
            self.running = False
            
        except KeyboardInterrupt:
            logger("info", "Keyboard interrupt received")
            self.running = False
        except Exception as e:
            logger("error", f"Main loop error: {e}")
        finally:
            # Funnel every exit path (timed, Ctrl-C via handler, KeyboardInterrupt
            # before the handler was installed, or an unexpected error) through
            # the one idempotent cleanup, so probes are always detached and
            # buffers flushed exactly once — the KeyboardInterrupt/error paths
            # used to skip detach + flush entirely. A no-op if cleanup already ran.
            self._cleanup(None, None)

            if self.verbose:
                actual_duration = time.time() - start
                logger("info", f"Trace completed after {actual_duration:.2f} seconds")

            self._log_block_diagnostics()
            # Finalise the manifest with stop time + final diagnostics. Guarded
            # so a manifest failure never blocks shutdown/flush.
            try:
                self._write_manifest(getattr(self, "_session_started_at", datetime.now()),
                                     datetime.now())
            except Exception as e:
                logger("warning", f"Could not finalise manifest.json: {e}")

            print()
            logger("info", "Trace stopped")

            run_with_spinner("Compressing trace output", self.writer.force_flush)

            if self.automatic_upload:
                # Drain the upload queue before stopping the workers — passing
                # False here set the stop event immediately and abandoned any
                # traces still queued for upload.
                run_with_spinner("Uploading traces", lambda: self.upload_manager.stop_worker(True, timeout=30))
                try:
                    os.removedirs(self.writer.output_dir)
                except OSError:
                    pass

            logger("info", "Cleanup complete. Exited successfully.")
