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
import shutil
import os
import time
import threading


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
        about each file found. Skips special filesystems and already-visited
        inodes to avoid duplicates.

        The first snapshot records every file (a full inventory). Every snapshot
        after that is a delta: a file is recorded only if it is new or its
        size/mtime/ctime changed since the previous completed snapshot, and
        files that disappeared are recorded as tombstone rows (size ==
        ``DELETED_SIZE``). access time (atime) is deliberately excluded from the
        change check since it changes on every read.

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

        def scan_dir(path: str, depth: int = 0):
            """Inner function for recursive directory scanning."""
            if self.interrupt or (max_depth is not None and depth > max_depth):
                return
            try:
                st = os.stat(path, follow_symlinks=False)
            except Exception:
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
                                ctime_ts = getattr(est, "st_birthtime", est.st_mtime)
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
                                scan_dir(entry.path, depth + 1)
                        except Exception:
                            continue
            except Exception:
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
