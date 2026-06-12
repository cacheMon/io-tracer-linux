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
from bcc import BPF
import time
import sys
from bisect import bisect_right
from pathlib import Path
from datetime import datetime

from .ObjectStorageManager import ObjectStorageManager
from ..utility.utils import capture_machine_id, format_csv_row, logger, hash_filename_in_path, simple_hash, run_with_spinner
from .WriterManager import WriteManager
from .FlagMapper import FlagMapper
from .KernelProbeTracker import KernelProbeTracker
from .PollingThread import PollingThread
from .PathResolver import PathResolver
from .snappers.FilesystemSnapper import FilesystemSnapper
from .snappers.ProcessSnapper import ProcessSnapper
from .snappers.SystemSnapper import SystemSnapper


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
        self.verbose            = verbose
        self.duration           = duration
        self.anonymous          = anonymous
        self.is_uncompressed    = is_uncompressed
        self.path_resolver      = PathResolver()
        self.mmap_regions       = {}
        self.cmdline_cache      = {}  # pid -> cmdline, populated on first successful read
        self._last_cache_cleanup = time.time()

        if cache_sample_rate > 1:
            self.writer.set_cache_sampling(cache_sample_rate)

        if page_cnt is None or page_cnt <= 0:
            logger("error", f"Invalid page count: {page_cnt}. Page count must be a positive integer.")
            sys.exit(1)
        self.page_cnt = page_cnt

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
                self.b = BPF(src_file=bpf_file.encode(), cflags=cflags)
                self.probe_tracker = KernelProbeTracker(self.b, developer_mode)

            run_with_spinner("Loading BPF program", _init_bpf)
        except Exception as e:
            logger("error", f"failed to initialize BPF: {e}")
            print("Your device are incompatible with this version of IO Tracer. Please notify us at io-tracer@googlegroups.com")
            sys.exit(1)

    def _should_filter_process(self, comm: str) -> bool:
        """Helper to filter out I/O unrelated system processes."""
        prefixes = ("swapper/", "ksoftirqd/", "irq/", "migration/", "stopper/")
        return comm.startswith(prefixes)

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
        event = self.b["events"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename = event.filename.decode()
            if self.anonymous:
                filename = hash_filename_in_path(Path(filename))
            if op_name in ['MKDIR', 'RMDIR', 'CHDIR', 'READDIR'] and filename and not filename.endswith('/'):
                filename += '/'
        except UnicodeDecodeError:
            filename = ""
        
        timestamp = datetime.today()
        
        try:
            comm = event.comm.decode()
        except UnicodeDecodeError:
            comm = "[decode_error]"
            
        if self._should_filter_process(comm):
            return
            
        inode_val = event.inode if event.inode != 0 else ""
        
        size_val = event.size if event.size is not None else 0
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
            else:
                cached = self.path_resolver.inode_to_path.get(event.inode)
                if cached:
                    filename = cached

        if raw_address:
            if op_name == "MMAP":
                self._track_mmap_region(event.pid, raw_address, size_val, filename)
            elif op_name == "MUNMAP":
                resolved_filename = self._resolve_munmap_filename(event.pid, raw_address, size_val)
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
                event.pid, old_addr_val, old_size_val, raw_address, size_val
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
        if op_name in ("READ", "WRITE"):
            ret = event.ret_val
            return_value = str(ret)
            if ret < 0:
                errno_val = self.flag_mapper.format_errno(-ret)
            else:
                bytes_completed = str(ret)
            duration_ns = str(event.latency_ns) if event.latency_ns else ""

        # Provenance metadata — populated for READ/WRITE/OPEN.
        dev_val = self._format_dev(event.dev) if getattr(event, "dev", 0) else ""
        ppid_val = event.ppid if getattr(event, "ppid", 0) else ""
        container_id = event.cgroup_id if getattr(event, "cgroup_id", 0) else ""
        fs_type_val = (
            self.flag_mapper.format_fs_type(event.fs_magic)
            if getattr(event, "fs_magic", 0) else ""
        )

        output = format_csv_row(
            timestamp, op_name, event.pid, comm, filename, size_val, inode_val,
            flags_val, offset_val, tid_val, mmap_prot_val, mmap_flags_val,
            address_val, cmdline,
            return_value, errno_val, bytes_completed, duration_ns,
            dev_val, ppid_val, container_id, fs_type_val
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

    def _handle_process_exec(self, pid: int) -> None:
        """
        Clear the mmap_regions and cmdline caches for a PID on exec.

        execve() replaces the entire virtual address space, so all tracked
        mappings are immediately stale. The cmdline also changes (new argv),
        so flush the cache entry so the next read picks up the new cmdline.
        """
        self.mmap_regions.pop(pid, None)
        self.cmdline_cache.pop(pid, None)

    def _maybe_cleanup_caches(self) -> None:
        """
        Periodically bound the userspace caches during long traces.

        path_resolver.inode_to_path gains an entry for every opened inode and
        cmdline_cache for every observed PID; without pruning an indefinite
        trace grows them without bound.
        """
        now = time.time()
        if now - self._last_cache_cleanup < 60:
            return
        self._last_cache_cleanup = now
        self.path_resolver.cleanup_old_cache()
        # Keep the most recently added entries (insertion order) so cmdlines
        # for recently exited PIDs — the reason this cache exists — survive;
        # entries for live PIDs are re-read on demand if dropped.
        if len(self.cmdline_cache) > 20000:
            self.cmdline_cache = dict(list(self.cmdline_cache.items())[-5000:])

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
        event = self.b["events_dual"].event(data)
        op_name = self.flag_mapper.op_fs_types.get(event.op, "[unknown]")
        
        try:
            filename_old = event.filename_old.decode()
            filename_new = event.filename_new.decode()
            if self.anonymous:
                filename_old = hash_filename_in_path(Path(filename_old))
                filename_new = hash_filename_in_path(Path(filename_new))
        except UnicodeDecodeError:
            filename_old = ""
            filename_new = ""
        
        timestamp = datetime.today()
        
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

        # Emit the same 22-column schema as _print_event so the shared fs log
        # stays a well-formed CSV. Dual-path ops (RENAME/LINK/SYMLINK) do not
        # carry offset/tid/mmap/address or the READ/WRITE/OPEN completion and
        # provenance fields, so those columns are empty.
        output = format_csv_row(
            timestamp, op_name, event.pid, comm, dual_filename, 0, inode_val,
            flags_val, "", "", "", "",   # offset, tid, mmap_prot, mmap_flags
            "", cmdline,                 # address, cmdline
            "", "", "", "",              # return_value, errno, bytes_completed, duration_ns
            "", "", "", ""               # device, ppid, container_id, fs_type
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
        timestamp = datetime.today()
        pid = event.pid
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

        output = format_csv_row(timestamp, pid, comm, event_name, inode, index, size, cpu_id, dev_id, count)

        self.writer.append_cache_log(output)

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
        
        timestamp = datetime.today()
        pid = event.pid
        tid = event.tid
        comm = event.comm.decode('utf-8', errors='replace')
        
        if self._should_filter_process(comm):
            return
            
        sector = event.sector
        ops_str = event.op.decode('utf-8', errors='replace')
        ops_str = self.flag_mapper.format_block_ops(ops_str)
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
        
        output = format_csv_row(timestamp, pid, comm, sector, ops_str, bio_size, latency_ms, tid, cpu_id, ppid, dev_str, queue_time_ms, cmd_flags_str, op_code_str)


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
        timestamp = datetime.today()
        
        pid = event.pid
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
        
        output = format_csv_row(timestamp, pid, tid, comm, fault_type, major, inode, offset, address, dev_id)
        self.writer.append_pagefault_log(output)

    def _print_event_io_uring(self, cpu, data, size):
        """
        Callback for processing io_uring events from the perf buffer.
        
        Captures io_uring async I/O operations including:
        - ENTER: io_uring_enter syscall
        - SUBMIT: Individual SQE submissions
        - COMPLETE: Request completions with latency
        - WORKER: Async worker executions
        
        Args:
            cpu: CPU number where the event was captured
            data: Raw event data pointer
            size: Size of the event data
        """
        e = self.b["io_uring_events"].event(data)
        ts = datetime.today()
        
        comm = e.comm.decode("utf-8", errors="replace").strip("\x00")
        
        if self._should_filter_process(comm):
            return
            
        event_type = self.flag_mapper.format_io_uring_event_type(e.event_type)
        opcode = self.flag_mapper.format_io_uring_opcode(e.opcode) if e.opcode else ""
        enter_flags = self.flag_mapper.format_io_uring_enter_flags(e.enter_flags) if e.enter_flags else ""
        sqe_flags = self.flag_mapper.format_io_uring_sqe_flags(e.sqe_flags) if e.sqe_flags else ""
        
        # Format fields based on event type
        ring_fd = str(e.ring_fd) if e.ring_fd else ""
        ring_ptr = hex(e.ring_ptr) if e.ring_ptr else ""
        to_submit = str(e.to_submit) if e.to_submit else ""
        min_complete = str(e.min_complete) if e.min_complete else ""
        
        req_ptr = hex(e.req_ptr) if e.req_ptr else ""
        user_data = str(e.user_data) if e.user_data else ""
        fd = str(e.fd) if e.fd != 0 and e.fd != -1 else ""
        length = str(e.len) if e.len else ""
        offset = str(e.offset) if e.offset else ""
        ioprio = str(e.ioprio) if e.ioprio else ""
        buf_index = str(e.buf_index) if e.buf_index else ""
        personality = str(e.personality) if e.personality else ""
        
        result = str(e.result) if e.result != 0 or e.event_type == 2 else ""
        is_error = "1" if e.is_error else ""
        cqe_errno = str(e.cqe_errno) if e.cqe_errno else ""
        
        submit_ts = str(e.submit_ts_ns) if e.submit_ts_ns else ""
        complete_ts = str(e.complete_ts_ns) if e.complete_ts_ns else ""
        latency_ns = str(e.latency_ns) if e.latency_ns else ""
        
        worker_pid = str(e.worker_pid) if e.worker_pid else ""
        worker_tid = str(e.worker_tid) if e.worker_tid else ""
        worker_cpu = str(e.worker_cpu) if e.worker_cpu else ""
        is_async = "1" if e.is_async else ""
        
        sq_head = str(e.sq_head) if e.sq_head else ""
        sq_tail = str(e.sq_tail) if e.sq_tail else ""
        cq_head = str(e.cq_head) if e.cq_head else ""
        cq_tail = str(e.cq_tail) if e.cq_tail else ""
        sq_depth = str(e.sq_depth) if e.sq_depth else ""
        cq_depth = str(e.cq_depth) if e.cq_depth else ""

        # File correlation — the prep probe records the backing file's inode,
        # device and filesystem for file-backed ops. Resolve the path from the
        # inode→path cache populated by OPEN events (same strategy as VFS events)
        # so io_uring I/O carries the same file identity as the fs trace.
        inode_val = e.inode if getattr(e, "inode", 0) else ""
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
                filename = hash_filename_in_path(Path(filename))

        # Surface io_uring file READ/WRITE in the main fs/VFS trace stream so
        # async I/O appears alongside syscall reads/writes. Mirror only on
        # COMPLETE (result/latency known) and only read/write opcodes, which
        # bypass vfs_read/vfs_write and would otherwise be invisible there.
        if e.event_type == 2:
            self._mirror_io_uring_to_fs(e, comm, filename, ts, dev_val, fs_type_val)

        # Build CSV row matching the unified schema from the guide
        output = format_csv_row(
            ts.strftime("%Y-%m-%d %H:%M:%S.%f"),
            str(e.timestamp_ns),
            event_type,
            str(e.pid),
            str(e.tid),
            comm,
            str(e.cpu),
            ring_fd,
            ring_ptr,
            to_submit,
            min_complete,
            enter_flags,
            req_ptr,
            user_data,
            opcode,
            fd,
            length,
            offset,
            sqe_flags,
            ioprio,
            buf_index,
            personality,
            result,
            is_error,
            cqe_errno,
            submit_ts,
            complete_ts,
            latency_ns,
            worker_pid,
            worker_tid,
            worker_cpu,
            is_async,
            sq_head,
            sq_tail,
            cq_head,
            cq_tail,
            sq_depth,
            cq_depth,
            inode_val,
            filename,
            dev_val,
            fs_type_val,
        )
        self.writer.append_io_uring_log(output)

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

        ret = e.result
        return_value = str(ret)
        errno_val = ""
        bytes_completed = ""
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
            ts, op_name, e.pid, comm, filename, size_val, e.inode,
            flags_val, offset_val, tid_val, "", "", "", cmdline,
            return_value, errno_val, bytes_completed, duration_ns,
            dev_val, "", "", fs_type_val
        )
        self.writer.append_fs_log(output)

    def _cleanup(self, signum, frame):
        self.running = False
        self.probe_tracker.detach_kprobes()

        def _flush():
            self.fs_snapper.stop_snapper()
            self.process_snapper.stop_snapper()
            self.writer.write_to_disk()
            self.writer.close_handles()

        run_with_spinner("Flushing trace data", _flush)

    def _lost_cb(self, lost):
        """
        Callback for handling lost events in the perf buffer.
        
        Args:
            lost: Number of events that were lost
        """
        if lost > 0:
            if self.verbose:
                logger("warning", f"Lost {lost} events in kernel buffer")

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
            page_cnt=self.page_cnt, 
            lost_cb=self._lost_cb
        )

        self.b["events_dual"].open_perf_buffer(
            self._print_event_dual,
            page_cnt=self.page_cnt,
            lost_cb=self._lost_cb
        )

        self.b["bl_events"].open_perf_buffer(
            self._print_event_block, 
            page_cnt=self.page_cnt, 
            lost_cb=self._lost_cb
        )

        # self.b["cache_events"].open_perf_buffer(
        #     self._print_event_cache, 
        #     page_cnt=self.page_cnt, 
        #     lost_cb=self._lost_cb
        # )

        # Page fault events for mmap I/O tracking
        # try:
        #     self.b["pagefault_events"].open_perf_buffer(
        #         self._print_event_pagefault,
        #         page_cnt=self.page_cnt,
        #         lost_cb=self._lost_cb
        #     )
        # except KeyError:
        #     if self.verbose:
        #         logger("warning", "pagefault_events buffer not available")

        # io_uring events for async I/O tracking
        try:
            self.b["io_uring_events"].open_perf_buffer(
                self._print_event_io_uring,
                page_cnt=self.page_cnt,
                lost_cb=self._lost_cb
            )
        except KeyError:
            if self.verbose:
                logger("warning", "io_uring_events buffer not available")

        start = time.time()
        if self.duration is not None:
            duration_target = self.duration
            end_time = start + duration_target
            logger("info", f"Tracing for {duration_target} seconds...")
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")

        # Start the polling thread for perf buffer
        self.polling_thread = PollingThread(self.b, True)
        self.polling_thread.create_thread()

        try:
            if self.duration is not None:
                remaining = duration_target # type: ignore
                while remaining > 0 and self.running:
                    sleep_time = min(0.1, remaining)
                    time.sleep(sleep_time)
                    self._maybe_cleanup_caches()

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
                    self._maybe_cleanup_caches()

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
            self.polling_thread.polling_active = False
            time.sleep(0.2)
            
            if self.verbose:
                actual_duration = time.time() - start
                logger("info", f"Trace completed after {actual_duration:.2f} seconds")
            
            print()
            logger("info", "Trace stopped")

            run_with_spinner("Compressing trace output", self.writer.force_flush)

            if self.automatic_upload:
                # server_mode=True drains the queue before stopping the worker;
                # otherwise the final bundle queued by force_flush above may
                # never be uploaded (the worker stops before picking it up).
                run_with_spinner("Uploading traces", lambda: self.upload_manager.stop_worker(True, timeout=60))
                try:
                    os.removedirs(self.writer.output_dir)
                except OSError:
                    pass

            logger("info", "Cleanup complete. Exited successfully.")
