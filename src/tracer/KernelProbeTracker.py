"""
KernelProbeTracker - Manages kernel probe (kprobe) attachment and detachment.

This module provides the KernelProbeTracker class which handles the lifecycle
of kernel probes used to intercept I/O system calls in the Linux kernel.

The tracker supports:
- Kprobes: One-shot probes for function entry
- Kretprobes: Return probes for function exit
- Multiple probe attachment with automatic cleanup
- Kernel version compatibility checks

Example:
    tracker = KernelProbeTracker(bpf_instance)
    tracker.attach_probes()  # Attach all probes
    # ... tracing operations ...
    tracker.detach_kprobes()  # Cleanup when done
"""

import ctypes
import os
from bcc import BPF
import sys
from ..utility.utils import logger


class KernelProbeTracker:
    """
    Manages kernel probe attachment and detachment for eBPF tracing.
    
    This class handles the registration of kprobes and kretprobes on various
    Linux kernel functions related to file I/O operations. It provides:
    - Probe addition (kprobe and kretprobe)
    - Probe detachment (cleanup)
    - Automatic kernel version compatibility detection
    
    Attributes:
        kprobes: List of attached kprobe tuples (event_name, kprobe_object)
        kretprobes: List of attached kretprobe tuples (event_name, kprobe_object)
        b: Reference to the BPF instance
    """
    
    def __init__(self, b: BPF, developer_mode: bool = False, trace_cache: bool = False):
        """
        Initialize the KernelProbeTracker.

        Args:
            b: BPF instance obtained from BCC library
            developer_mode: Enable verbose probe attachment logging
            trace_cache: Attach the page-cache probes. Off by default because the
                cache hit/miss probes are very high frequency; leaving them
                detached keeps overhead at zero when cache tracing is not wanted.

        Initializes empty lists for kprobes and kretprobes,
        stores the BPF reference, and configures the tracer PID
        for excluding the tracer process from traces.
        """
        self.kprobes = []
        self.kretprobes = []
        self.b = b
        self.developer_mode = developer_mode
        self.trace_cache = trace_cache

        tracer_pid = os.getpid()
        config_key = ctypes.c_uint32(0) 
        pid_value = ctypes.c_uint32(tracer_pid)
        self.b["tracer_config"][config_key] = pid_value


    def add_kprobe(self, event: str, kprobe: str) -> bool:
        """
        Attach a kprobe (kernel function entry probe).
        
        Args:
            event: Kernel function name to probe (e.g., "vfs_read")
            kprobe: Name of the BPF function to call when probe triggers
            
        Returns:
            bool: True if attachment succeeded, False otherwise (best-effort —
            a probe that cannot attach is skipped, not fatal).
        """
        try:
            # logger("info", f"Attaching kprobe {event} to {kprobe}")
            k = self.b.attach_kprobe(event=event, fn_name=kprobe)
            self.kprobes.append((event, k))
            return True
        except Exception as e:
            # Best-effort: a single missing/un-kprobe-able symbol (inlined, or
            # renamed across kernels/arches — many call sites here have no arch
            # fallback) must not abort the whole tracer. Skip it and continue;
            # attach_probes() aborts only if NOTHING attached (see its tail).
            logger("warning", f"Failed to attach kprobe {event} (skipping): {e}")
            return False

    # Number of concurrently in-flight probed-function instances a kretprobe can
    # track. The kernel default is small (≈NR_CPUS), so for hot functions like
    # vfs_read/vfs_write the return handler is silently missed once concurrency
    # exceeds it ("nmissed"). Each miss leaves a staged entry uncollected; with
    # LRU staging maps that just costs an event, but a large maxactive keeps the
    # miss rate (and lost events) low under load.
    KRETPROBE_MAXACTIVE = 4096

    def add_kretprobe(self, event: str, kprobe: str) -> bool:
        """
        Attach a kretprobe (kernel function return probe).

        Args:
            event: Kernel function name to probe (e.g., "vfs_read")
            kprobe: Name of the BPF function to call when probe triggers

        Returns:
            bool: True if attachment succeeded, False otherwise (best-effort —
            a probe that cannot attach is skipped, not fatal).
        """
        try:
            # logger("info", f"Attaching kprobe {event} to {kprobe}")
            try:
                k = self.b.attach_kretprobe(
                    event=event, fn_name=kprobe, maxactive=self.KRETPROBE_MAXACTIVE
                )
            except TypeError:
                # Older bcc without the maxactive kwarg: fall back to the default.
                k = self.b.attach_kretprobe(event=event, fn_name=kprobe)
            self.kretprobes.append((event, k))
            return True
        except Exception as e:
            # Best-effort, as in add_kprobe: skip a probe that can't attach on
            # this kernel/arch rather than killing the entire tracing session.
            logger("warning", f"Failed to attach kretprobe {event} (skipping): {e}")
            return False
        
    def detach_kprobes(self):
        """
        Detach all attached kprobes and kretprobes.
        
        Iterates through all registered probes and safely detaches them
        from the kernel. Errors during detachment are logged but do not
        raise exceptions.
        """
        # Detach kprobes
        for event, k in self.kprobes:
            try:
                self.b.detach_kprobe(event=event)
                # logger("info", f"Detached kprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

        # Detach kretprobes
        for event, k in self.kretprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def detach_kretprobes(self):
        """
        Detach all kretprobes only.
        """
        for event, k in self.kretprobes:
            try:
                self.b.detach_kretprobe(event=event)
                # logger("info", f"Detached kretprobe: {event}")
            except Exception as e:
                logger("error", f"Error detaching {event}: {e}")

    def attach_probes(self):
        """
        Attach all kernel probes for I/O tracing.
        
        This method attaches kprobes to various kernel functions related to:
        - Virtual File System (VFS) operations: read, write, open, close, etc.
        - Memory mapping: mmap, munmap
        - Directory operations: readdir, unlink
        - Attribute operations: getattr, setattr
        - Cache operations: hit, miss, dirty, writeback, eviction, etc.
        
        The method performs kernel version compatibility checks and uses
        fallback probes when primary functions are not available.
        
        Raises:
            SystemExit: If no probes can be attached successfully
        """
        try:
            # VFS (Virtual File System) probes
            self.add_kprobe("vfs_read", "trace_vfs_read")
            self.add_kprobe("vfs_write", "trace_vfs_write")
            # Return probes complete READ/WRITE events with the syscall return
            # value (bytes moved / errno) and the operation latency.
            self.add_kretprobe("vfs_read", "trace_vfs_read_ret")
            self.add_kretprobe("vfs_write", "trace_vfs_write_ret")
            # Capture the user-provided filename before the kernel resolves it.
            # Must be registered BEFORE vfs_open so the path is staged in time.
            # Uses the same fallback chain as the kretprobe.
            # NOTE: __x64_sys_* wrappers take a single pt_regs* holding the
            # user registers, so they need the *_x64 probe variants that
            # unwrap it; reading PARM1-4 directly there yields garbage.
            if BPF.get_kprobe_functions(b'do_sys_openat2'):
                self.add_kprobe("do_sys_openat2", "trace_do_sys_openat2_entry")
            elif BPF.get_kprobe_functions(b'__x64_sys_openat'):
                self.add_kprobe("__x64_sys_openat", "trace_openat_entry_x64")
            else:
                self.add_kprobe("sys_openat", "trace_do_sys_openat2_entry")
            self.add_kprobe("vfs_open", "trace_vfs_open")
            # kretprobe to complete the staged OPEN event with the real fd.
            # do_sys_openat2 is the primary target (kernel 5.6+); fall back to
            # the arch-specific wrapper or the old sys_openat on older kernels.
            if BPF.get_kprobe_functions(b'do_sys_openat2'):
                self.add_kretprobe("do_sys_openat2", "trace_sys_openat_ret")
            elif BPF.get_kprobe_functions(b'__x64_sys_openat'):
                self.add_kretprobe("__x64_sys_openat", "trace_sys_openat_ret")
            else:
                self.add_kretprobe("sys_openat", "trace_sys_openat_ret")
            self.add_kprobe("vfs_fsync", "trace_vfs_fsync")
            # Return probe clears the marker that suppresses the duplicate
            # event from the nested vfs_fsync -> vfs_fsync_range call.
            self.add_kretprobe("vfs_fsync", "trace_vfs_fsync_ret")
            self.add_kprobe("ksys_sync", "trace_ksys_sync")
            self.add_kprobe("vfs_fsync_range", "trace_vfs_fsync_range")
            self.add_kprobe("__fput", "trace_fput")
            
            # Memory mapping probes
            self.add_kprobe("do_mmap", "trace_mmap_entry")
            self.add_kretprobe("do_mmap", "trace_mmap_ret")
            self.add_kprobe("__vm_munmap", "trace_munmap")

            # mremap probes — kernel may export the arch wrapper or the generic
            # symbol. The wrapper needs the pt_regs-unwrapping variant.
            if BPF.get_kprobe_functions(b'__x64_sys_mremap'):
                self.add_kprobe("__x64_sys_mremap", "trace_mremap_entry_x64")
                self.add_kretprobe("__x64_sys_mremap", "trace_mremap_ret")
            elif BPF.get_kprobe_functions(b'sys_mremap'):
                self.add_kprobe("sys_mremap", "trace_mremap_entry")
                self.add_kretprobe("sys_mremap", "trace_mremap_ret")
            else:
                if self.developer_mode:
                    logger("warning", "mremap probe not available on this kernel version")
            
            # File attribute probes
            self.add_kprobe("vfs_getattr", "trace_vfs_getattr")
            self.add_kprobe("notify_change", "trace_vfs_setattr") 
            
            # Directory operation probes
            self.add_kprobe("iterate_dir", "trace_readdir")
            self.add_kprobe("vfs_unlink", "trace_vfs_unlink")
            self.add_kprobe("do_truncate", "trace_vfs_truncate")
            
            # New filesystem operation probes
            self.add_kprobe("vfs_rename", "trace_vfs_rename")
            self.add_kprobe("vfs_mkdir", "trace_vfs_mkdir")
            self.add_kprobe("vfs_rmdir", "trace_vfs_rmdir")
            self.add_kprobe("vfs_link", "trace_vfs_link")
            self.add_kprobe("vfs_symlink", "trace_vfs_symlink")
            self.add_kprobe("vfs_fallocate", "trace_vfs_fallocate")
            
            # Try to attach sendfile probe (may not be available on all kernels).
            # The kretprobe records the actual transferred byte count (the entry
            # ``count`` arg is only the requested ceiling, often SSIZE_MAX).
            if BPF.get_kprobe_functions(b'do_sendfile'):
                self.add_kprobe("do_sendfile", "trace_sendfile")
                self.add_kretprobe("do_sendfile", "trace_sendfile_ret")
            elif BPF.get_kprobe_functions(b'__do_sendfile'):
                self.add_kprobe("__do_sendfile", "trace_sendfile")
                self.add_kretprobe("__do_sendfile", "trace_sendfile_ret")
            else:
                if self.developer_mode:
                    logger("warning", "sendfile probe not available on this kernel version")

            # Splice probe for zero-copy transfers
            if BPF.get_kprobe_functions(b'do_splice'):
                self.add_kprobe("do_splice", "trace_splice")
            else:
                if self.developer_mode:
                    logger("warning", "splice probe not available on this kernel version")
            
            # Page fault probe for mmap I/O tracking
            # if BPF.get_kprobe_functions(b'filemap_fault'):
            #     self.add_kprobe("filemap_fault", "trace_filemap_fault_entry")
            #     logger("info", "Page fault tracing enabled via filemap_fault")
            # else:
            #     logger("warning", "filemap_fault not available - mmap I/O tracking disabled")
            
            # Direct I/O probes. The entry probe stages the I/O direction from
            # the iov_iter (the return value alone cannot distinguish a read
            # from a write); the return probe emits the completion event.
            if BPF.get_kprobe_functions(b'iomap_dio_rw'):
                self.add_kprobe("iomap_dio_rw", "trace_dio_entry_iomap")
                self.add_kretprobe("iomap_dio_rw", "trace_dio_return")
                if self.developer_mode:
                    logger("info", "Direct I/O tracing enabled via iomap_dio_rw")
            elif BPF.get_kprobe_functions(b'__blockdev_direct_IO'):
                self.add_kprobe("__blockdev_direct_IO", "trace_dio_entry_blockdev")
                self.add_kretprobe("__blockdev_direct_IO", "trace_dio_return")
                if self.developer_mode:
                    logger("info", "Direct I/O tracing enabled via __blockdev_direct_IO")
            else:
                if self.developer_mode:
                    logger("warning", "Direct I/O probe not available on this kernel version")
            
            # Page-cache probes. Off by default (opt-in via --cache) because the
            # cache hit/miss probes fire on essentially every page access and are
            # the highest-overhead probes in the tracer. Missing-function warnings
            # are gated on developer_mode to avoid noise when a kernel lacks a
            # given symbol.
            if self.trace_cache:
                # Cache Miss probes - kernel version dependent
                if BPF.get_kprobe_functions(b'filemap_add_folio'):
                    self.add_kprobe("filemap_add_folio", "trace_filemap_add_folio")
                elif BPF.get_kprobe_functions(b'add_to_page_cache_lru'):
                    self.add_kprobe("add_to_page_cache_lru", "trace_miss")
                elif self.developer_mode:
                    logger("warning", "No cache miss probe available")

                # Cache Hit probes - kernel version dependent
                if BPF.get_kprobe_functions(b'folio_mark_accessed'):
                    self.add_kprobe("folio_mark_accessed", "trace_folio_mark_accessed")
                elif BPF.get_kprobe_functions(b'mark_page_accessed'):
                    self.add_kprobe("mark_page_accessed", "trace_hit")
                elif self.developer_mode:
                    logger("warning", "No cache hit probe available")

                # Dirty Page probes - kernel version dependent
                if BPF.get_kprobe_functions(b'__folio_mark_dirty'):
                    self.add_kprobe("__folio_mark_dirty", "trace_folio_mark_dirty")
                elif BPF.get_kprobe_functions(b'account_page_dirtied'):
                    self.add_kprobe("account_page_dirtied", "trace_account_page_dirtied")
                elif self.developer_mode:
                    logger("warning", "No dirty page probe available")

                # Writeback Start probes - kernel version dependent
                if BPF.get_kprobe_functions(b'folio_clear_dirty_for_io'):
                    self.add_kprobe("folio_clear_dirty_for_io", "trace_folio_clear_dirty_for_io")
                elif BPF.get_kprobe_functions(b'clear_page_dirty_for_io'):
                    self.add_kprobe("clear_page_dirty_for_io", "trace_clear_page_dirty_for_io")
                elif self.developer_mode:
                    logger("warning", "No writeback start probe available")

                # Writeback End probes - kernel version dependent
                if BPF.get_kprobe_functions(b'folio_end_writeback'):
                    self.add_kprobe("folio_end_writeback", "trace_folio_end_writeback")
                elif BPF.get_kprobe_functions(b'__folio_end_writeback'):
                    self.add_kprobe("__folio_end_writeback", "trace_folio_end_writeback")
                elif BPF.get_kprobe_functions(b'test_clear_page_writeback'):
                    self.add_kprobe("test_clear_page_writeback", "trace_test_clear_page_writeback")
                elif self.developer_mode:
                    logger("warning", "No writeback end probe available")

                # Eviction probes - kernel version dependent
                if BPF.get_kprobe_functions(b'filemap_remove_folio'):
                    self.add_kprobe("filemap_remove_folio", "trace_filemap_remove_folio")
                elif BPF.get_kprobe_functions(b'__filemap_remove_folio'):
                    self.add_kprobe("__filemap_remove_folio", "trace_filemap_remove_folio")
                elif BPF.get_kprobe_functions(b'__delete_from_page_cache'):
                    self.add_kprobe("__delete_from_page_cache", "trace_delete_from_page_cache")
                elif self.developer_mode:
                    logger("warning", "No eviction probe available")

                # Cache invalidation probes
                if BPF.get_kprobe_functions(b'invalidate_mapping_pages'):
                    self.add_kprobe("invalidate_mapping_pages", "trace_invalidate_mapping")
                elif self.developer_mode:
                    logger("warning", "invalidate_mapping_pages not found, invalidation events may be incomplete")

                if BPF.get_kprobe_functions(b'truncate_inode_pages_range'):
                    self.add_kprobe("truncate_inode_pages_range", "trace_truncate_pages")
                elif self.developer_mode:
                    logger("warning", "truncate_inode_pages_range not found")

                # Cache drop probes - kernel version dependent
                # Avoid attaching to a function already used by eviction probes
                attached_events = {event for event, _ in self.kprobes}
                if BPF.get_kprobe_functions(b'__filemap_remove_folio') and '__filemap_remove_folio' not in attached_events:
                    # Kernel 5.18+ uses this for explicit page removal
                    self.add_kprobe("__filemap_remove_folio", "trace_cache_drop_folio")
                elif BPF.get_kprobe_functions(b'delete_from_page_cache') and 'delete_from_page_cache' not in attached_events:
                    # Older kernels
                    self.add_kprobe("delete_from_page_cache", "trace_cache_drop_page")
                elif BPF.get_kprobe_functions(b'__delete_from_page_cache') and '__delete_from_page_cache' not in attached_events:
                    # Fallback for some kernel versions
                    self.add_kprobe("__delete_from_page_cache", "trace_cache_drop_page")
                elif self.developer_mode:
                    logger("warning", "No cache drop function found, drop events will not be traced")

                # Cache readahead probes - track prefetch operations
                if BPF.get_kprobe_functions(b'__do_page_cache_readahead'):
                    self.add_kprobe("__do_page_cache_readahead", "trace_do_page_cache_readahead")
                elif BPF.get_kprobe_functions(b'do_page_cache_ra'):
                    self.add_kprobe("do_page_cache_ra", "trace_do_page_cache_readahead")
                elif BPF.get_kprobe_functions(b'page_cache_ra_order'):
                    # Newer kernels (5.16+)
                    self.add_kprobe("page_cache_ra_order", "trace_do_page_cache_readahead")
                elif self.developer_mode:
                    logger("warning", "No readahead probe available, readahead events will not be traced")

                # Cache reclaim probes - track memory pressure evictions
                if BPF.get_kprobe_functions(b'shrink_folio_list'):
                    # Newer kernels with folio
                    self.add_kprobe("shrink_folio_list", "trace_shrink_folio_list")
                elif BPF.get_kprobe_functions(b'shrink_page_list'):
                    # Older kernels
                    self.add_kprobe("shrink_page_list", "trace_shrink_folio_list")
                elif self.developer_mode:
                    logger("warning", "No reclaim probe available, reclaim events will not be traced")

            # =====================================
            # io_uring probes for async I/O tracing
            # =====================================
            # Note: io_uring tracepoints are preferred when available (kernel 5.6+)
            # The tracepoints are automatically attached via TRACEPOINT_PROBE macros in BPF code
            # We also attach kprobes as fallback for kernels without stable tracepoints
            
            # io_uring_enter syscall probe
            if BPF.get_kprobe_functions(b'__io_uring_enter'):
                self.add_kprobe("__io_uring_enter", "trace_io_uring_enter")
                if self.developer_mode:
                    logger("info", "io_uring tracing enabled via __io_uring_enter")
            elif BPF.get_kprobe_functions(b'__x64_sys_io_uring_enter'):
                # Syscall wrapper: needs the pt_regs-unwrapping variant.
                self.add_kprobe("__x64_sys_io_uring_enter", "trace_io_uring_enter_x64")
                if self.developer_mode:
                    logger("info", "io_uring tracing enabled via __x64_sys_io_uring_enter")
            elif BPF.get_kprobe_functions(b'__sys_io_uring_enter'):
                self.add_kprobe("__sys_io_uring_enter", "trace_io_uring_enter")
                if self.developer_mode:
                    logger("info", "io_uring tracing enabled via __sys_io_uring_enter")
            else:
                if self.developer_mode:
                    logger("warning", "io_uring_enter probe not available - ENTER events disabled")

            # io_uring SQE field capture (opcode/fd/len/offset/user_data + backing
            # file). The SUBMIT kprobe on io_queue_sqe only has the io_kiocb, whose
            # layout is not ABI-stable; the read/write prep handler receives the
            # UAPI io_uring_sqe (stable offsets) and the io_kiocb, so we capture the
            # SQE fields there and stage them for the SUBMIT/COMPLETE probes. The
            # shared helper io_prep_rw covers all rw opcodes; fall back to the
            # per-op prep handlers when it is inlined/renamed on a given kernel.
            prep_attached = False
            for sym in (b'io_prep_rw', b'__io_prep_rw'):
                if BPF.get_kprobe_functions(sym):
                    self.add_kprobe(sym.decode(), "trace_io_uring_prep_rw")
                    prep_attached = True
                    if self.developer_mode:
                        logger("info", f"io_uring SQE capture enabled via {sym.decode()}")
                    break
            if not prep_attached:
                for sym in (b'io_prep_readv', b'io_prep_writev',
                            b'io_prep_read', b'io_prep_write',
                            b'io_prep_read_fixed', b'io_prep_write_fixed'):
                    if BPF.get_kprobe_functions(sym):
                        self.add_kprobe(sym.decode(), "trace_io_uring_prep_rw")
                        prep_attached = True
                if self.developer_mode and prep_attached:
                    logger("info", "io_uring SQE capture enabled via per-op prep handlers")
            if not prep_attached and self.developer_mode:
                logger("warning", "io_uring SQE prep probe not available - opcode/fd/len/offset may be empty")

            # io_uring SQE submission probe (kprobe fallback for SUBMIT events)
            # Note: TRACEPOINT_PROBE(io_uring, io_uring_submit_sqe) in BPF is preferred
            if BPF.get_kprobe_functions(b'io_queue_sqe'):
                self.add_kprobe("io_queue_sqe", "trace_io_uring_submit")
                if self.developer_mode:
                    logger("info", "io_uring SQE submission tracing enabled via io_queue_sqe")
            elif BPF.get_kprobe_functions(b'io_submit_sqe'):
                self.add_kprobe("io_submit_sqe", "trace_io_uring_submit")
                if self.developer_mode:
                    logger("info", "io_uring SQE submission tracing enabled via io_submit_sqe")
            else:
                if self.developer_mode:
                    logger("info", "io_uring kprobe submit fallback not found - using tracepoint only")

            # io_uring completion probe (kprobe fallback for COMPLETE events)
            # Note: TRACEPOINT_PROBE(io_uring, io_uring_complete) in BPF is preferred
            if BPF.get_kprobe_functions(b'io_req_complete_post'):
                self.add_kprobe("io_req_complete_post", "trace_io_uring_complete")
                if self.developer_mode:
                    logger("info", "io_uring completion tracing enabled via io_req_complete_post")
            elif BPF.get_kprobe_functions(b'__io_req_complete'):
                self.add_kprobe("__io_req_complete", "trace_io_uring_complete")
                if self.developer_mode:
                    logger("info", "io_uring completion tracing enabled via __io_req_complete")
            elif BPF.get_kprobe_functions(b'io_req_complete'):
                self.add_kprobe("io_req_complete", "trace_io_uring_complete")
                if self.developer_mode:
                    logger("info", "io_uring completion tracing enabled via io_req_complete")
            else:
                if self.developer_mode:
                    logger("info", "io_uring kprobe complete fallback not found - using tracepoint only")

            # io_uring async worker probe (io-wq)
            if BPF.get_kprobe_functions(b'io_wq_submit_work'):
                self.add_kprobe("io_wq_submit_work", "trace_io_uring_worker")
                if self.developer_mode:
                    logger("info", "io_uring worker tracing enabled via io_wq_submit_work")
            elif BPF.get_kprobe_functions(b'io_worker_handle_work'):
                self.add_kprobe("io_worker_handle_work", "trace_io_uring_worker")
                if self.developer_mode:
                    logger("info", "io_uring worker tracing enabled via io_worker_handle_work")
            else:
                if self.developer_mode:
                    logger("warning", "io_uring worker probe not available - WORKER events disabled")

            if not self.kprobes:
                logger("error", "no kprobes attached successfully!")
                sys.exit(1)   
        except Exception as e:
            logger("error", f"failed to attach to kernel functions: {e}")
            sys.exit(1)
