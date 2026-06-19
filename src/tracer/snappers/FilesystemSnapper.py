"""
FilesystemSnapper - Captures filesystem snapshots during tracing.

This module provides the FilesystemSnapper class which walks the filesystem
hierarchy and records information about files at trace time. This provides
context for understanding which files existed during the trace.

The snapper can operate in two modes:
- Normal: Records actual file paths
- Anonymous: Records hashed/anonymized paths

To avoid re-uploading the entire filesystem inventory on every hourly pass,
the snapper is delta-based after the first run: the first snapshot is a full
inventory of every file, and each subsequent snapshot records only the files
that were added, modified, or deleted since the previous completed snapshot.
Deleted files are recorded as a tombstone row whose size is ``DELETED_SIZE``
(-1). A delta with no changes produces no output (and therefore no upload).

Example:
    snapper = FilesystemSnapper(writer_manager=wm, anonymous=False)
    snapper.run()  # Start snapshot in background thread
    snapper.stop_snapper()  # Stop the snapper
"""

from ...utility.utils import format_csv_row, logger, compress_log, anonymize_path
from ..WriterManager import WriteManager
from datetime import datetime
import ctypes
import shutil
import os
import time
import threading


# --- Real file birth time via statx() -------------------------------------
# Linux os.stat() never exposes st_birthtime, so the creation_time column used
# to be a verbatim copy of mtime. statx(2) with STATX_BTIME returns the true
# inode birth time on filesystems that record it (ext4, xfs, btrfs, ...). We
# call libc's statx() through ctypes and fall back to mtime when the syscall,
# libc symbol, or the per-file btime is unavailable.
_AT_FDCWD = -100
_AT_SYMLINK_NOFOLLOW = 0x100
_STATX_BTIME = 0x00000800


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_nsec", ctypes.c_uint32),
        ("__reserved", ctypes.c_int32),
    ]


class _Statx(ctypes.Structure):
    # Layout per <linux/stat.h> struct statx. Only fields up to stx_btime are
    # read; the remainder is reserved padding sized to the kernel struct.
    _fields_ = [
        ("stx_mask", ctypes.c_uint32),
        ("stx_blksize", ctypes.c_uint32),
        ("stx_attributes", ctypes.c_uint64),
        ("stx_nlink", ctypes.c_uint32),
        ("stx_uid", ctypes.c_uint32),
        ("stx_gid", ctypes.c_uint32),
        ("stx_mode", ctypes.c_uint16),
        ("__spare0", ctypes.c_uint16),
        ("stx_ino", ctypes.c_uint64),
        ("stx_size", ctypes.c_uint64),
        ("stx_blocks", ctypes.c_uint64),
        ("stx_attributes_mask", ctypes.c_uint64),
        ("stx_atime", _StatxTimestamp),
        ("stx_btime", _StatxTimestamp),
        ("stx_ctime", _StatxTimestamp),
        ("stx_mtime", _StatxTimestamp),
        ("stx_rdev_major", ctypes.c_uint32),
        ("stx_rdev_minor", ctypes.c_uint32),
        ("stx_dev_major", ctypes.c_uint32),
        ("stx_dev_minor", ctypes.c_uint32),
        ("__spare2", ctypes.c_uint64 * 14),
    ]


_statx_supported = True   # flips to False on first failure to avoid retry cost
_libc = None


def get_birth_time(path: str, fallback: float) -> float:
    """Return the file's birth time (epoch seconds) via statx STATX_BTIME.

    Falls back to ``fallback`` (typically mtime) when statx is unavailable or the
    filesystem does not record a birth time for this file. The first hard
    failure disables further attempts for the process lifetime.
    """
    global _statx_supported, _libc
    if not _statx_supported:
        return fallback
    try:
        if _libc is None:
            _libc = ctypes.CDLL("libc.so.6", use_errno=True)
            # Pin the signature so the pointer/path args are not truncated to
            # the default 32-bit int on a 64-bit platform.
            _libc.statx.argtypes = [
                ctypes.c_int,            # dirfd
                ctypes.c_char_p,         # pathname
                ctypes.c_int,            # flags
                ctypes.c_uint,           # mask
                ctypes.POINTER(_Statx),  # statxbuf
            ]
            _libc.statx.restype = ctypes.c_int
        buf = _Statx()
        rc = _libc.statx(_AT_FDCWD, os.fsencode(path), _AT_SYMLINK_NOFOLLOW,
                         _STATX_BTIME, ctypes.byref(buf))
        if rc != 0:
            # ENOSYS (syscall absent) or EPERM (blocked by seccomp) will never
            # succeed; disable for the process lifetime to avoid a failing
            # syscall on every file during the directory walk.
            err = ctypes.get_errno()
            if err in (1, 38):  # EPERM, ENOSYS
                _statx_supported = False
            return fallback
        if buf.stx_mask & _STATX_BTIME:
            return buf.stx_btime.tv_sec + buf.stx_btime.tv_nsec / 1e9
        return fallback
    except (OSError, AttributeError):
        # libc has no statx symbol (very old glibc) or it cannot be loaded.
        _statx_supported = False
        return fallback


# --- Pseudo-filesystem skipping via statfs() ------------------------------
# The live eBPF prober already drops procfs/sysfs/cgroup/... events at source
# (see prober.c is_pseudo_fs_magic). The periodic filesystem snapshot walks the
# tree from "/" in user space and, without the same filter, descends into
# /proc and /sys -- which dominate the inventory (e.g. /proc is the majority of
# rows and /proc/kcore reports a multi-petabyte sparse size that is meaningless
# for a storage census). We mirror the prober's denylist here by reading the
# superblock magic via statfs(2) so both paths share one definition of what a
# pseudo filesystem is.
#
# tmpfs and ramfs are deliberately NOT treated as pseudo (they hold real
# application data in /dev/shm and /tmp), matching the prober's NOTE.
_PSEUDO_FS_MAGICS = frozenset({
    0x9fa0,       # PROC_SUPER_MAGIC  -- /proc
    0x62656572,   # SYSFS_MAGIC       -- /sys
    0x9fa2,       # SOCKFS_MAGIC
    0x64626720,   # DEBUGFS_MAGIC
    0x1cd1,       # DEVPTS_SUPER_MAGIC
    0x74656d70,   # DEVTMPFS_MAGIC    -- /dev
    0x50495045,   # PIPEFS_MAGIC
    0x27e0eb,     # CGROUP_SUPER_MAGIC
    0xf97cff8c,   # SELINUX_MAGIC
    0xBAD1DEA,    # FUTEXFS_SUPER_MAGIC
    0x2BAD1DEA,   # INOTIFYFS_SUPER_MAGIC
    0xabba1974,   # XENFS_SUPER_MAGIC
    0x67596969,   # RPCAUTH_GSSMAGIC
    0x74726163,   # TRACEFS_MAGIC
    0x63677270,   # CGROUP2_SUPER_MAGIC
    0xCAFE4A11,   # BPF_FS_MAGIC
    0x19800202,   # mqueue / eventpoll / aio-ring family
})


class _Statfs(ctypes.Structure):
    # Layout of glibc `struct statfs` on 64-bit Linux. Only f_type (the first
    # word, carrying the superblock magic) is read; the rest is declared so the
    # buffer is correctly sized for the syscall to write into.
    _fields_ = [
        ("f_type", ctypes.c_int64),
        ("f_bsize", ctypes.c_int64),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_namelen", ctypes.c_int64),
        ("f_frsize", ctypes.c_int64),
        ("f_flags", ctypes.c_int64),
        ("f_spare", ctypes.c_int64 * 4),
    ]


_statfs_supported = True   # flips to False on first hard failure


def is_pseudo_fs(path: str) -> bool:
    """Return True if ``path`` lives on a pseudo/virtual filesystem.

    Reads the superblock magic via statfs(2) and matches it against the same
    denylist the eBPF prober uses. Fails open (returns False) when statfs is
    unavailable or errors, so an undeterminable filesystem is still inventoried
    rather than silently dropped -- we would rather over-include than lose real
    storage from the census.
    """
    global _statfs_supported, _libc
    if not _statfs_supported:
        return False
    try:
        if _libc is None:
            _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        # statfs is resolved lazily; pin its signature once available.
        if not getattr(_libc.statfs, "_iotracer_pinned", False):
            _libc.statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(_Statfs)]
            _libc.statfs.restype = ctypes.c_int
            _libc.statfs._iotracer_pinned = True
        buf = _Statfs()
        rc = _libc.statfs(os.fsencode(path), ctypes.byref(buf))
        if rc != 0:
            err = ctypes.get_errno()
            if err == 38:  # ENOSYS -- statfs absent, never retry
                _statfs_supported = False
            return False
        # Mask to 32 bits: the kernel stores the magic in a signed word and
        # several magics (e.g. SELINUX 0xf97cff8c) have the high bit set.
        return (buf.f_type & 0xFFFFFFFF) in _PSEUDO_FS_MAGICS
    except (OSError, AttributeError):
        _statfs_supported = False
        return False


# Size value written for a file that disappeared since the previous snapshot.
# In delta snapshots a deleted file is emitted as a tombstone row carrying this
# sentinel so consumers can distinguish removals from added/modified files
# (which always carry a real, non-negative byte count).
DELETED_SIZE = -1


class FilesystemSnapper:
    """
    Captures filesystem snapshots for trace context.
    
    This class traverses the filesystem tree and records information
    about files, including paths, sizes, and timestamps. This data
    provides context for understanding the system state during tracing.
    
    Attributes:
        anonymous: Whether to anonymize file paths
        root_path: Root directory to scan (default: "/")
        interrupt: Flag to stop the snapshot thread
        wm: WriteManager for outputting data
        _visited_inodes: Set of visited inode keys to avoid duplicates
        _root_dev: Device ID of root filesystem
        
    Example:
        snapper = FilesystemSnapper(wm, anonymous=True)
        snapper.run()
        # ... later ...
        snapper.stop_snapper()
    """
    
    def __init__(self, wm: WriteManager, anonymous: bool = False):
        """
        Initialize the FilesystemSnapper.
        
        Args:
            wm: WriteManager for outputting snapshot data
            anonymous: Whether to hash file paths (default: False)
        """
        self.anonymous = anonymous
        self.root_path = "/"
        self.interrupt = False
        self.wm = wm
        self._visited_inodes = set()
        # Delta tracking. After the first full snapshot, only changes are
        # recorded. ``_prev_state`` maps real (un-anonymized) path ->
        # (size, mtime, ctime, atime) as captured by the last completed
        # snapshot; ``_have_full_snapshot`` flips to True once a full snapshot
        # has finished without being interrupted.
        self._prev_state = {}
        self._have_full_snapshot = False

    def filesystem_snapshot(self, max_depth: int = None):
        """
        Perform a filesystem snapshot by walking the directory tree.

        Recursively scans directories up to max_depth, recording information
        about each file found. Pseudo filesystems (procfs, sysfs, cgroup, ...)
        are skipped at their mount points via statfs() so the inventory stays
        focused on durable storage, mirroring the eBPF prober's denylist.
        Already-visited inodes are skipped to avoid duplicates.

        The first snapshot records every file (a full inventory). Every snapshot
        after that is a delta: a file is recorded only if it is new or its
        size/mtime/ctime changed since the previous completed snapshot, and
        files that disappeared are recorded as tombstone rows (size ==
        ``DELETED_SIZE``). access time (atime) is deliberately excluded from the
        change check since it changes on every read.

        Deletion detection distinguishes a genuine removal from a transient
        read failure: if a file or directory cannot be stat'd/scanned because of
        a transient error (e.g. a permission error), its previous state is
        carried forward so it is not falsely tombstoned. Only paths that are
        actually absent (or whose containing directory was fully scanned without
        them) become tombstones.

        Args:
            max_depth: Maximum directory depth to traverse (default: None = unlimited)

        Returns:
            bool: True if snapshot completed naturally, False if interrupted
        """
        # Capture snapshot timestamp once for all files in this snapshot.
        # Millisecond resolution to match the process snapshot stream.
        snapshot_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        # Common cross-stream clock, captured once for the whole snapshot.
        snapshot_mono_ns = time.monotonic_ns()
        count = 0
        is_delta = self._have_full_snapshot
        # Full state captured this pass: real path -> (size, mtime, ctime, atime).
        # Built for every file (changed or not) so it becomes the baseline for
        # the next delta and so we can detect deletions against the previous one.
        new_state = {}

        def emit(path: str, size, mtime_ts: float, ctime_ts: float, atime_ts: float):
            """Write one snapshot row, anonymizing the path when configured."""
            nonlocal count
            out_path = (
                anonymize_path(path, keep_ext=True, length=12)
                if self.anonymous else path
            )
            out = format_csv_row(
                snapshot_timestamp, out_path, size,
                datetime.fromtimestamp(ctime_ts),
                datetime.fromtimestamp(mtime_ts),
                datetime.fromtimestamp(atime_ts),
                snapshot_mono_ns,
            )
            self.wm.append_fs_snap_log(out)
            count += 1

        def is_transient(exc: Exception) -> bool:
            """True for errors that mean "couldn't read it this pass" rather than
            "it's gone". A transient failure (e.g. PermissionError, an I/O error,
            or a momentary lock) must not be mistaken for a deletion; an absence
            error (the path really vanished) should fall through to a tombstone.
            """
            return not isinstance(exc, (FileNotFoundError, NotADirectoryError))

        def carry_over_subtree(dir_path: str):
            """Preserve the previous snapshot's entries under ``dir_path`` so a
            directory we transiently failed to read is not mistaken for the
            deletion of everything inside it. ``setdefault`` avoids clobbering
            entries already captured this pass (e.g. before a mid-scan failure).
            """
            prefix = dir_path if dir_path.endswith(os.sep) else dir_path + os.sep
            for p, meta in self._prev_state.items():
                if p.startswith(prefix):
                    new_state.setdefault(p, meta)

        def scan_dir(path: str, depth: int = 0, parent_dev=None):
            """Inner function for recursive directory scanning."""
            if self.interrupt or (max_depth is not None and depth > max_depth):
                return
            try:
                st = os.stat(path, follow_symlinks=False)
            except Exception as e:
                # Couldn't stat the directory itself. Only carry its contents
                # forward when the failure is transient; if it genuinely no
                # longer exists, let its files fall through to tombstones.
                if is_delta and is_transient(e):
                    carry_over_subtree(path)
                return

            # At every mount boundary (the device id differs from the parent,
            # or this is the root of the walk) check whether we have crossed
            # into a pseudo filesystem -- /proc, /sys, cgroup, etc. -- and if so
            # skip the whole subtree. These carry no durable storage and would
            # otherwise dominate the inventory. Gating on the device change keeps
            # this to one statfs() per mount rather than one per directory.
            if st.st_dev != parent_dev and is_pseudo_fs(path):
                return

            key = (st.st_dev, st.st_ino)
            if key in self._visited_inodes:
                return
            self._visited_inodes.add(key)

            try:
                with os.scandir(path) as it:
                    for entry in it:
                        if self.interrupt:
                            return
                        try:
                            if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                                est = entry.stat(follow_symlinks=False)
                                size = est.st_size
                                mtime_ts = est.st_mtime
                                ctime_ts = get_birth_time(entry.path, est.st_mtime)
                                atime_ts = est.st_atime
                                new_state[entry.path] = (size, mtime_ts, ctime_ts, atime_ts)

                                # In delta mode, skip files whose size/mtime/ctime
                                # are unchanged from the previous snapshot.
                                if is_delta:
                                    prev = self._prev_state.get(entry.path)
                                    if prev is not None and prev[:3] == (size, mtime_ts, ctime_ts):
                                        continue

                                emit(entry.path, size, mtime_ts, ctime_ts, atime_ts)
                            elif entry.is_dir(follow_symlinks=False):
                                scan_dir(entry.path, depth + 1, st.st_dev)
                        except Exception as e:
                            # Couldn't read this entry. On a transient failure
                            # keep its previous state so a file we merely failed
                            # to stat is not reported as deleted; a genuinely
                            # missing entry falls through to the deletion pass.
                            if is_delta and is_transient(e):
                                prev = self._prev_state.get(entry.path)
                                if prev is not None:
                                    new_state.setdefault(entry.path, prev)
                            continue
            except Exception as e:
                # Couldn't list the directory's contents. Same rule: carry the
                # subtree forward on a transient failure, tombstone on absence.
                if is_delta and is_transient(e):
                    carry_over_subtree(path)
                return

        logger("info", f"Filesystem Snapshot: session started ({'delta' if is_delta else 'full'})")
        scan_dir(self.root_path, 0)

        # Record removals: any path present last time but not seen now. Only
        # meaningful for a delta, and only when the scan finished naturally (an
        # interrupted scan hasn't visited every directory, so absence is not a
        # reliable signal of deletion).
        if is_delta and not self.interrupt:
            for path, (size, mtime_ts, ctime_ts, atime_ts) in self._prev_state.items():
                if self.interrupt:
                    break
                if path not in new_state:
                    emit(path, DELETED_SIZE, mtime_ts, ctime_ts, atime_ts)

        print(f"Filesystem Snapshot: {count} {'changes' if is_delta else 'files'} captured")
        # Only flush, mark complete, and advance the baseline if not interrupted
        if not self.interrupt:
            self.wm.flush_fssnap_only()
            self.wm.mark_fs_snapshot_complete()
            # This completed scan becomes the baseline for the next delta.
            self._prev_state = new_state
            self._have_full_snapshot = True
            # logger("info", "Filesystem snapshot completed.")
            return True
        else:
            # Snapshot was interrupted - don't mark as complete or advance the
            # baseline. The incomplete snapshot handling in force_flush() cleans
            # it up; the next pass retries against the same previous baseline.
            return False

    def stop_snapper(self):
        """Signal the snapshot thread to stop."""
        self.interrupt = True

    def get_file_size(self, path: str) -> int:
        """
        Get the size of a file.
        
        Args:
            path: Path to the file
            
        Returns:
            int: File size in bytes, or -1 if file cannot be accessed
        """
        try:
            return os.path.getsize(path)
        except (OSError, FileNotFoundError):
            return -1

    def _snapshot_loop(self):
        """Loop that runs snapshots every hour."""
        last_snapshot_time = None
        
        while not self.interrupt:
            current_time = time.time()
            
            # Check if we should take a snapshot
            if last_snapshot_time is None:
                # First snapshot - run immediately
                completed = self.filesystem_snapshot()
                if completed:
                    last_snapshot_time = time.time()
            else:
                # Check if one hour has passed since last snapshot
                time_since_last_snapshot = current_time - last_snapshot_time
                if time_since_last_snapshot >= 3600:  # 3600 seconds = 1 hour
                    # Reset visited inodes before new snapshot (they are per
                    # walk). _prev_state is intentionally NOT cleared: it is the
                    # baseline the next snapshot diffs against to upload a delta.
                    self._visited_inodes.clear()
                    completed = self.filesystem_snapshot()
                    if completed:
                        last_snapshot_time = time.time()
                    last_snapshot_time = time.time()
                else:
                    # Less than one hour ago - sleep 1 minute
                    time.sleep(60)

    def run(self):
        """Start the snapshot in a background daemon thread."""
        snapper_thread = threading.Thread(target=self._snapshot_loop)
        snapper_thread.daemon = True
        snapper_thread.start()
