"""
PathResolver - Real-time path resolver for inode-to-path mapping.

This module provides the PathResolver class which maintains a cache
of inode-to-path mappings by reading from /proc/<pid>/fd for active processes.
This is useful for resolving file paths when only inode numbers are available
during tracing.

The resolver maintains two caches:
- inode_to_path: Global mapping of inode numbers to file paths
- pid_to_files: Per-process mapping of open file descriptors

Example:
    resolver = PathResolver(cache_timeout=10)
    path = resolver.resolve_open_path(pid=1234, inode=12345, filename="file.txt")
    path = resolver.resolve_path(inode=12345, pid=1234, filename="unknown")
"""

import os
import time
from pathlib import Path


class PathResolver:
    """
    Real-time path resolver that maps inodes to file paths.
    
    This class provides on-the-fly path resolution by reading from
    /proc/<pid>/fd for running processes. It maintains caches to
    avoid repeated filesystem lookups.
    
    The resolver is useful when tracing systems where filenames may
    not be directly available (e.g., when only inode is captured).
    
    Attributes:
        inode_to_path: Dict mapping inode numbers to resolved paths
        pid_to_files: Dict mapping PIDs to their open file mappings
        cache_timeout: Seconds before cache entries expire
        last_update: Dict tracking last update time per PID
    """
    
    def __init__(self, cache_timeout: int = 10):
        """
        Initialize the PathResolver.
        
        Args:
            cache_timeout: Seconds before cache entries expire (default: 10)
        """
        self.inode_to_path = {}
        self.pid_to_files = {}
        self.cache_timeout = cache_timeout
        self.last_update = {}
        
    def update_process_files(self, pid: int) -> dict:
        """
        Update the file mapping for a specific process.
        
        Reads all file descriptors from /proc/<pid>/fd and builds
        a mapping from inode numbers to file paths.
        
        Args:
            pid: Process ID to update
            
        Returns:
            dict: Mapping of inode numbers to file paths for this process
            
        Note:
            This method skips special file descriptors like pipes,
            sockets, and anon_inode files.
        """
        try:
            current_time = time.time()
            
            # Check if cache is still valid
            if pid in self.last_update:
                if current_time - self.last_update[pid] < self.cache_timeout:
                    return self.pid_to_files.get(pid, {})
            
            files = {}
            fd_dir = f'/proc/{pid}/fd'
            
            if os.path.exists(fd_dir):
                for fd in os.listdir(fd_dir):
                    try:
                        link_path = os.path.join(fd_dir, fd)
                        target = os.readlink(link_path)
                        
                        # Only process regular files
                        if (not target.startswith('pipe:') and 
                            not target.startswith('socket:') and
                            not target.startswith('anon_inode:')):
                            
                            stat_info = os.stat(link_path)
                            inode = stat_info.st_ino
                            files[inode] = target
                            # Update global inode cache
                            self.inode_to_path[inode] = target
                    except OSError:
                        continue

            self.pid_to_files[pid] = files
            self.last_update[pid] = current_time
            return files

        except OSError:
            return {}
    
    def resolve_by_fd(self, pid: int, fd: int, inode: int = 0, filename: str = "") -> str:
        """
        Resolve the full path from a known file descriptor.

        A single ``os.readlink`` on ``/proc/<pid>/fd/<fd>`` — O(1), no scanning.
        This is the preferred method when the fd is available (i.e., for OPEN events
        captured via the openat kretprobe).

        On success the result is stored in ``inode_to_path`` so that subsequent
        READ/WRITE events on the same inode benefit without re-reading /proc.

        Args:
            pid:      Process ID that owns the file descriptor
            fd:       File descriptor number
            inode:    Inode number (optional) — used only to populate the cache
            filename: Basename fallback from eBPF if resolution fails

        Returns:
            str: Absolute path, or ``filename`` if resolution fails
        """
        if not pid or fd < 0:
            return filename

        try:
            target = os.readlink(f"/proc/{pid}/fd/{fd}")
            # Ignore pseudo-file FDs — they have no meaningful path
            if (target.startswith("pipe:") or
                    target.startswith("socket:") or
                    target.startswith("anon_inode:")):
                return filename
            # Populate inode cache so later READ/WRITE events are free
            if inode:
                self.inode_to_path[inode] = target
            return target
        except OSError:
            return filename

    def resolve_open_path(self, pid: int, inode: int, filename: str = "") -> str:
        """
        Resolve the full path for a freshly-opened file descriptor.

        Scans /proc/<pid>/fd/ immediately (no cache) and matches by inode.
        This is the preferred method for OPEN events because the file
        descriptor is guaranteed to still be alive at event time.

        Falls back to the basename from the eBPF event if resolution fails.

        Args:
            pid:      Process ID that opened the file
            inode:    Inode number captured by eBPF
            filename: Basename fallback from eBPF (may be empty)

        Returns:
            str: Full resolved path, or ``filename`` if resolution fails
        """
        if not pid or not inode:
            return filename

        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                link = os.path.join(fd_dir, fd)
                try:
                    target = os.readlink(link)
                    # Skip pipes, sockets, anon inodes - they have no real path
                    if (target.startswith("pipe:") or
                            target.startswith("socket:") or
                            target.startswith("anon_inode:")):
                        continue
                    stat_info = os.stat(link)
                    if stat_info.st_ino == inode:
                        # Populate the cache so later events benefit too
                        self.inode_to_path[inode] = target
                        return target
                except OSError:
                    continue
        except OSError:
            pass

        return filename

    def resolve_path(self, inode: int, pid: int | None = None, filename: str | None = None) -> str:
        """
        Resolve the full path for an inode.
        
        Attempts to resolve the path in this order:
        1. Check global inode cache
        2. Check process-specific cache if PID provided
        3. Return filename if provided and resolution fails
        
        Args:
            inode: Inode number to resolve
            pid: Optional process ID for process-specific lookup
            filename: Optional fallback filename if resolution fails
            
        Returns:
            str: Resolved path or fallback (filename or "[inode:X]")
        """
        
        # Try cache first
        if inode in self.inode_to_path:
            return self.inode_to_path[inode]
        
        # Try to resolve from process
        if pid:
            files = self.update_process_files(pid)
            if inode in files:
                return files[inode]
        
        # If we only have filename, return it
        return filename if filename else f"[inode:{inode}]"
    
    def cleanup_old_cache(self):
        """
        Remove old entries from cache to prevent memory bloat.

        Removes:
        - Process entries older than cache_timeout * 10 seconds
        - Limits inode cache to 5000 most recent entries

        Thread-safety: this runs on the polling thread (from the perf-buffer
        callbacks via cache maintenance), the same thread that mutates these
        dicts. Iteration still works on list() snapshots and removals
        tolerate missing entries as defense in depth.
        """
        current_time = time.time()

        # Clean up process cache
        pids_to_remove = []
        for pid, last_time in list(self.last_update.items()):
            if current_time - last_time > self.cache_timeout * 10:
                pids_to_remove.append(pid)

        for pid in pids_to_remove:
            self.pid_to_files.pop(pid, None)
            self.last_update.pop(pid, None)


        # Optionally limit inode cache size
        if len(self.inode_to_path) > 10000:
            # Keep only the most recent 5000 entries
            # This is a simple strategy; you might want something more sophisticated
            self.inode_to_path = dict(list(self.inode_to_path.items())[-5000:])
