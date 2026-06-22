"""
WriterManager - Manages writing trace data to files with buffering and compression.

This module provides the WriteManager class which handles:
- Creating output directory structure
- Buffering trace events for different subsystems
- Writing events to CSV files
- Compressing output files with Zstandard (.zst), or gzip (.gz) as a fallback
- Optionally uploading files to cloud storage

The manager uses adaptive buffering to handle high event rates and
supports multiple output streams (VFS, block, cache, etc.).

Example:
    writer = WriteManager(
        output_dir="/path/to/output",
        upload_manager=upload_manager,
        automatic_upload=True
    )
    writer.append_fs_log("event_data")
    writer.force_flush()  # Flush all buffers on shutdown
"""

import os
import sys
import json
from datetime import datetime
import tarfile

from .ObjectStorageManager import ObjectStorageManager
from . import schema
from ..utility.utils import (
    logger, capture_machine_id,
    compress_file, zstandard_available, ZSTD_LEVEL, GZIP_LEVEL,
)
import threading
from collections import deque
import shutil
import time


class WriteManager:
    """
    Manages writing trace data to disk with buffering and compression.
    
    This class handles all file I/O operations for the tracer, including:
    - Creating and managing output directories
    - Buffering events for different subsystems
    - Flushing buffers to CSV files
    - Compressing output files
    - Optional automatic upload
    
    Attributes:
        output_dir: Base directory for all output files
        upload_manager: ObjectStorageManager for uploads
        automatic_upload: Whether to auto-upload compressed files
        
    Output Files:
        fs/*.csv: File system operation traces
        block/*.csv: Block device traces
        cache/*.csv: Page cache event traces
        process/*.csv: Process state snapshots
        filesystem_snapshot/*.csv: Filesystem snapshot
        system_spec/*: System specification files
    """
    
    def __init__(self, output_dir: str, upload_manager: ObjectStorageManager, automatic_upload: bool):
        """
        Initialize the WriteManager.
        
        Args:
            output_dir: Base directory for output files
            upload_manager: ObjectStorageManager for uploads
            automatic_upload: Whether to auto-upload files
        """
        self.current_datetime = datetime.now()

        self.created_files = 0
        # created_files is bumped from several threads (perf-callback compress,
        # periodic-flush compress, and the snapshot thread's part upload). A
        # plain += is a non-atomic read-modify-write, so concurrent rotations
        # could lose increments and undercount this telemetry — guard it.
        self._created_files_lock = threading.Lock()
        # Total rows written to disk per stream (keyed by buffer label), for the
        # session manifest — lets a consumer spot a stream whose probes attached
        # but produced no events.
        self.rows_written = {}
        # Rows that could NOT be persisted (write/flush raised — e.g. ENOSPC /
        # EDQUOT / closed handle) and were dropped after exceeding the on-error
        # retry cap. Surfaced in the manifest so a consumer can tell honest data
        # loss apart from a complete stream — never silently swallowed.
        self.write_dropped = {}
        # Cap on rows re-queued for retry after a failed write, so a persistently
        # full/over-quota disk re-queues for transient errors but cannot grow the
        # in-memory buffers without bound (OOM). Oldest rows past the cap are
        # dropped and counted in ``write_dropped``.
        self._max_buffered_rows_on_error = 500_000
        self.last_status_log_time = time.time()
        self.status_log_interval = 60  # Log status every 60 seconds
        self.output_dir = output_dir
        self.output_vfs_file = f"{self.output_dir}/fs/fs_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_block_file = f"{self.output_dir}/block/block_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_cache_file = f"{self.output_dir}/cache/cache_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_fs_snapshot_file = f"{self.output_dir}/filesystem_snapshot/filesystem_snapshot_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        # Network streams (low-overhead subset: connection lifecycle, socket
        # options, drops). Files stay empty unless --network is enabled.
        self.output_nw_conn_file = f"{self.output_dir}/nw_conn/nw_conn_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_nw_sockopt_file = f"{self.output_dir}/nw_sockopt/nw_sockopt_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_nw_drop_file = f"{self.output_dir}/nw_drop/nw_drop_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

        # Create output directories
        os.makedirs(f"{self.output_dir}/system_spec", exist_ok=True)
        os.makedirs(f"{self.output_dir}/fs", exist_ok=True)
        os.makedirs(f"{self.output_dir}/block", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache", exist_ok=True)
        os.makedirs(f"{self.output_dir}/process", exist_ok=True)
        os.makedirs(f"{self.output_dir}/filesystem_snapshot", exist_ok=True)
        os.makedirs(f"{self.output_dir}/nw_conn", exist_ok=True)
        os.makedirs(f"{self.output_dir}/nw_sockopt", exist_ok=True)
        os.makedirs(f"{self.output_dir}/nw_drop", exist_ok=True)

        self.upload_manager = upload_manager
        self.automatic_upload = automatic_upload

        # Event buffers for each subsystem
        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()
        self.process_buffer = deque()
        self.fs_snap_buffer = deque()
        self.nw_conn_buffer = deque()
        self.nw_sockopt_buffer = deque()
        self.nw_drop_buffer = deque()

        # Event rate tracking
        self.event_timestamps = {
            'vfs': deque(maxlen=1000),
            'block': deque(maxlen=1000),
            'cache': deque(maxlen=1000),
            'fs_state': deque(maxlen=1000),
            'proc_state': deque(maxlen=1000),
            'nw_conn': deque(maxlen=1000),
            'nw_sockopt': deque(maxlen=1000),
            'nw_drop': deque(maxlen=1000),
        }
        
        # Dynamic thresholds (min, max). Raised roughly 10x from the original
        # sizes so each rotated/compressed log file is meaningfully larger,
        # producing fewer, larger per-stream uploads instead of many tiny ones.
        # The min is the steady-state file size at low event rates; the max
        # caps memory by bounding how many events a buffer holds in RAM.
        self.dynamic_limits = {
            'vfs': (80000, 800000),
            'block': (80000, 400000),
            'cache': (100000, 1000000),
            'fs_state': (80000, 200000),
            'proc_state': (80000, 100000),
        }
        
        # Start adaptive sizing thread
        self.adaptive_thread = threading.Thread(target=self._adaptive_sizing, daemon=True)
        self.adaptive_thread.start()
        
        # Start periodic flush thread (every 5 minutes)
        self._periodic_flush_active = True
        self._last_flush_time = time.time()
        self.periodic_flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.periodic_flush_thread.start()
        

        # Buffer flush thresholds. Raised ~10x so each rotated log file holds
        # more events and uploads larger (kept in sync with dynamic_limits).
        self.cache_max_events = 100000
        self.vfs_max_events = 80000
        self.block_max_events = 80000
        self.process_max_events = 80000  # Large enough to fit entire hourly snapshot
        self.fs_snap_max_events = 80000
        # Network streams are comparatively low-volume (no per-packet path), so a
        # fixed threshold is sufficient; they are not adaptively resized.
        self.nw_conn_max_events = 80000
        self.nw_sockopt_max_events = 80000
        self.nw_drop_max_events = 80000

        # Per-stream locks. Buffer flushes are triggered both from the
        # perf-callback (polling) thread via append_*_log -> flush_*_only and
        # from the periodic-flush thread via write_to_disk. Both paths open,
        # write, close and swap the same file handle, so each stream needs a
        # lock to avoid writing to a closed/stale handle or interleaving rows.
        self._stream_locks = {
            'vfs':       threading.Lock(),
            'block':     threading.Lock(),
            'cache':     threading.Lock(),
            'process':   threading.Lock(),
            'fs_snap':   threading.Lock(),
            'nw_conn':    threading.Lock(),
            'nw_sockopt': threading.Lock(),
            'nw_drop':    threading.Lock(),
        }

        # File handles for each output
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._process_handle = None
        self._fs_snap_handle = None
        self._nw_conn_handle = None
        self._nw_sockopt_handle = None
        self._nw_drop_handle = None

        # Registry of the continuous event streams that support generic
        # rotation. Snapshots (process, fs_snap) are intentionally excluded:
        # rotating one mid-session would split a single logical snapshot.
        # Each entry names the attributes that hold its buffer, file handle,
        # and current output path, plus its output subdir/prefix and log label.
        self._streams = {
            'vfs':       {'subdir': 'fs',        'prefix': 'fs',        'buf': 'vfs_buffer',       'handle': '_vfs_handle',       'file': 'output_vfs_file',       'log': 'VFS'},
            'block':     {'subdir': 'block',     'prefix': 'block',     'buf': 'block_buffer',     'handle': '_block_handle',     'file': 'output_block_file',     'log': 'Block'},
            'cache':     {'subdir': 'cache',     'prefix': 'cache',     'buf': 'cache_buffer',     'handle': '_cache_handle',     'file': 'output_cache_file',     'log': 'Cache'},
            'nw_conn':    {'subdir': 'nw_conn',    'prefix': 'nw_conn',    'buf': 'nw_conn_buffer',    'handle': '_nw_conn_handle',    'file': 'output_nw_conn_file',    'log': 'NetConn'},
            'nw_sockopt': {'subdir': 'nw_sockopt', 'prefix': 'nw_sockopt', 'buf': 'nw_sockopt_buffer', 'handle': '_nw_sockopt_handle', 'file': 'output_nw_sockopt_file', 'log': 'NetSockopt'},
            'nw_drop':    {'subdir': 'nw_drop',    'prefix': 'nw_drop',    'buf': 'nw_drop_buffer',    'handle': '_nw_drop_handle',    'file': 'output_nw_drop_file',    'log': 'NetDrop'},
        }

        # Time/size based rotation so a slow stream's log doesn't wait until
        # shutdown to upload. A stream's current file is rotated (compressed +
        # queued for upload) once it is older than max_file_age or larger than
        # max_file_bytes, even if it never reaches its event-count threshold.
        # Monotonic open-times so the age check ignores wall-clock jumps.
        self.max_file_age = 5 * 60                # 5 minutes
        self.max_file_bytes = 100 * 1024 * 1024   # 100 MB (uncompressed on disk)
        self._stream_opened = {key: time.monotonic() for key in self._streams}
        # Per-stream rotation sequence, appended to each rotated filename so two
        # rotations in the same millisecond can't collide on the timestamp.
        self._stream_seq = {key: 0 for key in self._streams}

        # Cache sampling configuration
        self.cache_sample_rate = 1  # Can be increased to reduce cache event volume
        self.cache_event_counter = 0

        # Filesystem snapshot multi-part tracking
        self.fs_snapshot_part_number = 1
        self.fs_snapshot_timestamp = None
        self.fs_snapshot_device_id = None
        self.fs_snapshot_session_active = False
        self.fs_snapshot_parts_pending_upload = []  # Track parts to upload after completion

        # Process snapshot session tracking
        self.process_snapshot_session_active = False

    # WriteManager stream key -> schema.STREAMS key.
    _SCHEMA_KEY = {
        'vfs': 'fs', 'block': 'block', 'cache': 'cache',
        'process': 'process', 'fs_snap': 'filesystem_snapshot',
        'nw_conn': 'nw_conn',
        'nw_sockopt': 'nw_sockopt', 'nw_drop': 'nw_drop',
    }

    def _open_log_file(self, path: str, wm_key: str, write_header: bool = True):
        """Open a stream's CSV for appending, writing the schema header row first
        when the file is new/empty so every (rotated) file is self-describing.

        ``write_header`` may be set False for the 2nd+ parts of a multi-part
        stream whose parts are meant to be concatenated back into one CSV: a
        header in every part would otherwise land as a bogus data row mid-table.
        """
        is_new = (not os.path.exists(path)) or os.path.getsize(path) == 0
        handle = open(path, 'a', buffering=8192)
        if is_new and write_header:
            handle.write(schema.header_line(self._SCHEMA_KEY[wm_key]) + "\n")
        return handle

    def _calculate_event_rate(self, event_type: str) -> float:
        """
        Calculate the event rate for a given event type.
        
        Args:
            event_type: Type of events ('vfs', 'block', 'cache', etc.)
            
        Returns:
            float: Events per second, or 0.0 if insufficient data
        """
        timestamps = self.event_timestamps[event_type]
        if len(timestamps) < 2:
            return 0.0
        
        time_span = timestamps[-1] - timestamps[0]
        if time_span <= 0:
            return 0.0
        
        return len(timestamps) / time_span

    def _adaptive_sizing(self):
        """
        Background thread that adjusts buffer thresholds based on event rates.
        
        Monitors event rates for each subsystem and adjusts buffer flush
        thresholds dynamically to handle high-load situations.
        """
        while True:
            time.sleep(10)  
            
            for event_type in ['vfs', 'block', 'cache', 'fs_state','proc_state']:
                rate = self._calculate_event_rate(event_type)
                min_limit, max_limit = self.dynamic_limits[event_type]
                
                if rate > 10000:  
                    new_limit = max_limit
                elif rate > 1000: 
                    new_limit = int(min_limit + (max_limit - min_limit) * 0.7)
                elif rate > 100: 
                    new_limit = int(min_limit + (max_limit - min_limit) * 0.4)
                else:  
                    new_limit = min_limit
                
                if event_type == 'vfs':
                    self.vfs_max_events = new_limit
                elif event_type == 'block':
                    self.block_max_events = new_limit
                elif event_type == 'cache':
                    self.cache_max_events = new_limit
                elif event_type == 'fs_state':
                    self.fs_snap_max_events = new_limit
                elif event_type == 'proc_state':
                    self.process_max_events = new_limit

    def _periodic_flush(self):
        """
        Background thread that flushes all buffers every 5 minutes.
        
        This ensures data is written to disk periodically even if buffers
        haven't reached their thresholds, preventing data loss and reducing
        memory usage during long traces. Timer resets after each manual flush.
        """
        flush_interval = 300  # 5 minutes in seconds
        
        while self._periodic_flush_active:
            time.sleep(10)  # Check every 10 seconds
            
            if not self._periodic_flush_active:
                break
            
            # Log status periodically
            status_elapsed = time.time() - self.last_status_log_time
            if status_elapsed >= self.status_log_interval:
                self._log_status()
                self.last_status_log_time = time.time()
                
            elapsed = time.time() - self._last_flush_time
            if elapsed >= flush_interval:
                try:
                    self.write_to_disk()
                    self._last_flush_time = time.time()
                except Exception as e:
                    logger("error", f"Error in periodic flush: {e}")

            # Rotate+upload any log that has grown too large or aged too long,
            # so slow streams don't defer their upload to shutdown.
            try:
                self._maybe_rotate_stale_logs()
            except Exception as e:
                logger("error", f"Error rotating stale logs: {e}")

    def _reset_flush_timer(self):
        """Reset the periodic flush timer (called after manual flushes)."""
        self._last_flush_time = time.time()

    def _log_status(self):
        """Log current buffer sizes and snapshot progress."""
        status_parts = []
        
        # Buffer sizes
        buffer_info = []
        if len(self.vfs_buffer) > 0:
            buffer_info.append(f"VFS:{len(self.vfs_buffer)}")
        if len(self.block_buffer) > 0:
            buffer_info.append(f"Block:{len(self.block_buffer)}")
        if len(self.cache_buffer) > 0:
            buffer_info.append(f"Cache:{len(self.cache_buffer)}")
        if buffer_info:
            status_parts.append(f"Buffers: {', '.join(buffer_info)}")
        
        # Snapshot status
        snapshot_info = []
        if self.fs_snapshot_session_active:
            parts_written = self.fs_snapshot_part_number - 1
            pending_events = len(self.fs_snap_buffer)
            snapshot_info.append(f"FS Snapshot: part {parts_written} ({pending_events} events buffered)")
        
        if self.process_snapshot_session_active:
            pending_events = len(self.process_buffer)
            snapshot_info.append(f"Process Snapshot: active ({pending_events} events buffered)")
        
        if snapshot_info:
            status_parts.append(f"Snapshots: {', '.join(snapshot_info)}")
        
        # Files created
        status_parts.append(f"Files Created: {self.created_files}")
        
        if status_parts:
            logger("info", f"Status - {' | '.join(status_parts)}", True)

    def set_cache_sampling(self, sample_rate: int):
        """
        Set the sampling rate for cache events.
        
        Args:
            sample_rate: N where only 1 in N events is recorded (default: 1 = no sampling)
        """
        self.cache_sample_rate = sample_rate
        logger("info", f"Cache sampling set to 1:{sample_rate} (every {sample_rate}th event)")

    # Buffer threshold check methods
    def should_flush_cache(self) -> bool:
        """Check if cache buffer should be flushed."""
        return (len(self.cache_buffer) >= self.cache_max_events)

    def should_flush_vfs(self) -> bool:
        """Check if VFS buffer should be flushed."""
        return (len(self.vfs_buffer) >= self.vfs_max_events)

    def should_flush_block(self) -> bool:
        """Check if block buffer should be flushed."""
        return (len(self.block_buffer) >= self.block_max_events)

    def should_flush_process(self) -> bool:
        """Check if process buffer should be flushed."""
        return (len(self.process_buffer) >= self.process_max_events)

    def should_flush_fssnap(self) -> bool:
        """Check if filesystem snapshot buffer should be flushed."""
        return (len(self.fs_snap_buffer) >= self.fs_snap_max_events)

    def append_fs_snap_log(self, log_output: str):
        """
        Add a filesystem snapshot log entry.
        
        Note: Does not auto-flush. Snapshots are flushed explicitly
        after completion to ensure one snapshot = one file.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            if self._fs_snap_handle is None:
                self._fs_snap_handle = self._open_log_file(self.output_fs_snapshot_file, 'fs_snap')
            self.fs_snap_buffer.append(log_output)
            self.event_timestamps['fs_state'].append(time.time())
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_fs_log(self, log_output: str):
        """
        Add a filesystem VFS log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.vfs_buffer.append(log_output)
            self.event_timestamps['vfs'].append(time.time())
            
            if self.should_flush_vfs():
                self.flush_vfs_only()
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_process_log(self, log_output: str):
        """
        Add a process state log entry.
        
        Note: Does not auto-flush. Snapshots are flushed explicitly
        after completion to ensure one snapshot = one file.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.process_buffer.append(log_output)
            self.event_timestamps['proc_state'].append(time.time())
        else:
            logger("error", "Invalid process log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        """
        Add a block device log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.block_buffer.append(log_output)
            self.event_timestamps['block'].append(time.time())
            
            if self.should_flush_block():
                self.flush_block_only()
        else:
            logger("error", "Invalid block log output format. Expected a string.")

    def append_cache_log(self, log_output: str):
        """
        Add a cache event log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.cache_event_counter += 1
            if self.cache_sample_rate > 1 and (self.cache_event_counter % self.cache_sample_rate) != 0:
                return 
            
            self.cache_buffer.append(log_output)
            self.event_timestamps['cache'].append(time.time())
            
            if self.should_flush_cache():
                self.flush_cache_only()
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def append_conn_log(self, log_output: str):
        """Add a network connection-lifecycle log entry."""
        if isinstance(log_output, str):
            self.nw_conn_buffer.append(log_output)
            self.event_timestamps['nw_conn'].append(time.time())
            if len(self.nw_conn_buffer) >= self.nw_conn_max_events:
                self._rotate_stream('nw_conn')
        else:
            logger("error", "Invalid connection log output format. Expected a string.")

    def append_sockopt_log(self, log_output: str):
        """Add a socket-option log entry."""
        if isinstance(log_output, str):
            self.nw_sockopt_buffer.append(log_output)
            self.event_timestamps['nw_sockopt'].append(time.time())
            if len(self.nw_sockopt_buffer) >= self.nw_sockopt_max_events:
                self._rotate_stream('nw_sockopt')
        else:
            logger("error", "Invalid sockopt log output format. Expected a string.")

    def append_drop_log(self, log_output: str):
        """Add a network drop/retransmit log entry."""
        if isinstance(log_output, str):
            self.nw_drop_buffer.append(log_output)
            self.event_timestamps['nw_drop'].append(time.time())
            if len(self.nw_drop_buffer) >= self.nw_drop_max_events:
                self._rotate_stream('nw_drop')
        else:
            logger("error", "Invalid drop log output format. Expected a string.")

    def direct_write(self, output_path: str, spec_str: str):
        """
        Write a system specification file directly.
        
        Args:
            output_path: Filename for the output
            spec_str: Content to write
        """
        try:
            dst = f"{self.output_dir}/system_spec/{output_path}"
            with open(dst, 'w') as f:
                f.write(spec_str)
            if self.automatic_upload:
                self.upload_manager.append_object(dst)
        except Exception as e:
            logger("error", f"Error writing device spec to {output_path}: {e}")

    def flush_fssnap_only(self):
        """
        Flush filesystem snapshot buffer to a multi-part file.

        Writes buffer to filesystem_snapshot_part####_TIMESTAMP_DEVICEID.csv,
        compresses it with Zstandard, and increments the part counter.
        """
        with self._stream_locks['fs_snap']:
            if not self.fs_snap_buffer:
                return
            # Initialize snapshot session if not already active
            if not self.fs_snapshot_session_active:
                self.start_fs_snapshot_session()

            # Generate part filename with zero-padded part number
            part_str = f"{self.fs_snapshot_part_number:04d}"
            part_filename = (
                f"filesystem_snapshot_part{part_str}_"
                f"{self.fs_snapshot_timestamp}_"
                f"{self.fs_snapshot_device_id}.csv"
            )
            part_filepath = f"{self.output_dir}/filesystem_snapshot/{part_filename}"

            # Open file handle for this part if needed. Only the first part
            # carries the schema header; the documented reader concatenates all
            # parts in order, so headers on parts 2+ would corrupt the table.
            if self._fs_snap_handle is None or self.output_fs_snapshot_file != part_filepath:
                if self._fs_snap_handle is not None:
                    self._fs_snap_handle.close()
                self._fs_snap_handle = self._open_log_file(
                    part_filepath, 'fs_snap',
                    write_header=(self.fs_snapshot_part_number == 1),
                )
                self.output_fs_snapshot_file = part_filepath

            # Write buffer to file
            self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")

            # Close handle before compression
            self._fs_snap_handle.close()
            self._fs_snap_handle = None

            # Compress the part, preferring Zstandard and falling back to gzip.
            if os.path.exists(part_filepath):
                # Don't log or count each part - we'll log when snapshot is complete
                compressed = compress_file(part_filepath)
                if compressed is not None and compressed != part_filepath:
                    os.remove(part_filepath)
                    part_output = compressed
                else:
                    part_output = part_filepath

                # Store for later upload (after snapshot completion and final part rename)
                if self.automatic_upload:
                    self.fs_snapshot_parts_pending_upload.append(part_output)
            else:
                logger("warning", f"Snapshot file not found for compression: {part_filepath}")

            # Increment part number for next flush
            self.fs_snapshot_part_number += 1

            # Log snapshot progress
            parts_written = self.fs_snapshot_part_number - 1
            logger("info", f"FS Snapshot: part {parts_written} written ({len(self.fs_snap_buffer)} events remain in buffer)")

            self._reset_flush_timer()

    def start_fs_snapshot_session(self):
        """
        Initialize a new filesystem snapshot session.
        
        Sets up timestamp, device ID, and resets part counter for a new
        multi-part filesystem snapshot.
        """
        self.fs_snapshot_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.fs_snapshot_device_id = capture_machine_id().upper()
        self.fs_snapshot_part_number = 1
        self.fs_snapshot_session_active = True
        self.fs_snapshot_parts_pending_upload.clear()  # Clear any previous session's pending uploads
        
    def mark_fs_snapshot_complete(self):
        """
        Mark the filesystem snapshot as complete.
        
        Renames the last part file to include '_complete_partsN' suffix
        indicating this is the final part and the total number of parts.
        """
        # Hold the fs_snap stream lock for the whole operation: the parallel
        # writer/flush threads compress and write parts under the same lock, so
        # renaming the last part here without it could race with an in-flight
        # write or compression.
        with self._stream_locks['fs_snap']:
            if not self.fs_snapshot_session_active:
                return

            total_parts = self.fs_snapshot_part_number - 1  # -1 because we increment after each flush

            if total_parts < 1:
                # No parts were written
                self.fs_snapshot_session_active = False
                return

            # Find the last part file. It is normally Zstandard-compressed
            # (.csv.zst), but with gzip fallback it is .csv.gz, and if no codec
            # was available it stays uncompressed (.csv); detect whichever
            # actually exists so the completion rename stays correct.
            last_part_str = f"{total_parts:04d}"
            snapshot_dir = f"{self.output_dir}/filesystem_snapshot"
            base_name = (
                f"filesystem_snapshot_part{last_part_str}_"
                f"{self.fs_snapshot_timestamp}_"
                f"{self.fs_snapshot_device_id}"
            )
            suffix = ".csv.zst"
            for candidate in (".csv.zst", ".csv.gz", ".csv"):
                if os.path.exists(f"{snapshot_dir}/{base_name}{candidate}"):
                    suffix = candidate
                    break
            old_filepath = f"{snapshot_dir}/{base_name}{suffix}"

            # Construct new filename with completion marker
            new_filepath = (
                f"{snapshot_dir}/{base_name}_complete_parts{total_parts}{suffix}"
            )

            # Rename the file (only if it still exists locally)
            try:
                if os.path.exists(old_filepath):
                    os.rename(old_filepath, new_filepath)
                    logger("info", f"Filesystem snapshot complete: {total_parts} parts written")

                    # Update the pending upload list with the new filename
                    if self.automatic_upload and old_filepath in self.fs_snapshot_parts_pending_upload:
                        self.fs_snapshot_parts_pending_upload.remove(old_filepath)
                        self.fs_snapshot_parts_pending_upload.append(new_filepath)
                else:
                    # File doesn't exist (may have been already processed)
                    logger("info", f"Filesystem snapshot complete: {total_parts} parts written")

                # Upload all parts now that snapshot is complete
                if self.automatic_upload:
                    num_parts = len(self.fs_snapshot_parts_pending_upload)
                    if num_parts > 0:
                        # Count each part individually to match upload counter
                        total_created = self._bump_created_files(num_parts)
                        logger('info', f"Files Created: {str(total_created)} (filesystem snapshot with {num_parts} parts)", True)
                    for part_file in self.fs_snapshot_parts_pending_upload:
                        if os.path.exists(part_file):
                            self.upload_manager.append_object(part_file)
                    self.fs_snapshot_parts_pending_upload.clear()

            except Exception as e:
                logger("error", f"Failed to process final snapshot part: {e}")

            # Reset session
            self.fs_snapshot_session_active = False

    def start_process_snapshot_session(self):
        """Mark the beginning of a process snapshot session."""
        self.process_snapshot_session_active = True
        logger("info", "Process Snapshot: session started")

    def flush_process_state_only(self):
        """Flush process state buffer to file."""
        rotated = None
        with self._stream_locks['process']:
            if self.process_buffer:
                if self._process_handle is None:
                    self._process_handle = self._open_log_file(self.output_process_file, 'process')
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")
                self._process_handle.close()
                rotated = self.output_process_file
                self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
                # Reopen LAZILY (on the next append) rather than eagerly: an eager
                # _open_log_file here writes a schema header into the new file
                # immediately, so the LAST snapshot before shutdown left a
                # header-only, 0-data-row file that force_flush still compressed +
                # uploaded (a stray part; a bogus 2nd header to a concatenating
                # reader). With None, the file is created only when there is a row
                # to write, and force_flush's compress_log skips the missing path.
                self._process_handle = None
                self._reset_flush_timer()

                # Mark process snapshot as complete
                self.process_snapshot_session_active = False
                logger("info", "Process Snapshot: completed and flushed")
        if rotated is not None:
            self.compress_log(rotated)

    def flush_cache_only(self):
        """Flush cache buffer to file (rotate + compress + upload)."""
        self._rotate_stream('cache')

    def flush_vfs_only(self):
        """Flush VFS buffer to file (rotate + compress + upload)."""
        self._rotate_stream('vfs')

    def flush_block_only(self):
        """Flush block buffer to file (rotate + compress + upload)."""
        self._rotate_stream('block')

    def _rotate_stream(self, key: str):
        """Rotate one continuous stream's current log and queue it for upload.

        Flushes any buffered rows into the current file, closes it, swaps in a
        fresh timestamped output file, and compresses/uploads the rotated one.
        Works whether the rows are still buffered (event-count flush) or were
        already written to disk by the periodic writer (time/size rotation).
        A no-op when there is nothing on disk or buffered to rotate.
        """
        s = self._streams[key]
        rotated = None
        with self._stream_locks[key]:
            buf = getattr(self, s['buf'])
            handle = getattr(self, s['handle'])
            cur_file = getattr(self, s['file'])

            # Land any buffered rows in the current file first.
            if buf:
                if handle is None:
                    handle = self._open_log_file(cur_file, key)
                    setattr(self, s['handle'], handle)
                self.current_datetime = datetime.now()
                self._write_buffer_to_file(buf, handle, s['log'])

            # Close before compressing so we never compress/delete an open file.
            if handle is not None:
                handle.close()
                setattr(self, s['handle'], None)

            # Skip rotating an empty file (avoids zero-byte uploads); just keep
            # appending to it.
            if not os.path.exists(cur_file) or os.path.getsize(cur_file) == 0:
                setattr(self, s['handle'], self._open_log_file(cur_file, key))
                return

            rotated = cur_file
            self._stream_seq[key] += 1
            new_file = (
                f"{self.output_dir}/{s['subdir']}/{s['prefix']}_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}_"
                f"{self._stream_seq[key]:04d}.csv"
            )
            setattr(self, s['file'], new_file)
            setattr(self, s['handle'], self._open_log_file(new_file, key))
            self._stream_opened[key] = time.monotonic()
            # NOTE: do NOT reset the periodic-flush timer here. A single stream's
            # count-based rotation must not defer the global periodic write_to_disk
            # of every OTHER stream: on a busy host fs/cache rotate every few
            # seconds, so resetting the timer here starved write_to_disk entirely,
            # leaving low-volume buffers (network especially) unwritten — and thus
            # unrotated/un-uploaded — until shutdown. _maybe_rotate_stale_logs is
            # now buffer-aware so slow streams still upload mid-trace regardless.
        # Compress outside the lock: compression + disk I/O is slow and must not block
        # the perf-callback flush or the periodic writer for this stream.
        if rotated is not None:
            self.compress_log(rotated)

    def _maybe_rotate_stale_logs(self, now: float | None = None):
        """Rotate continuous logs that have grown too large or aged too long.

        Lets a slow stream upload mid-trace instead of waiting until shutdown:
        any stream whose current file exceeds ``max_file_bytes`` or has been
        open longer than ``max_file_age`` is rotated and queued for upload.
        ``now`` is an injectable ``time.monotonic()`` reading for testing.

        Buffered-but-unwritten rows count toward "has data": a low-volume stream
        (network especially) may hold its rows in the in-memory buffer with an
        empty on-disk file, because the periodic disk flush can be starved on a
        busy host. Rotating on age still flushes those rows — _rotate_stream
        lands the buffer into the file first — so the stream uploads mid-trace
        instead of deferring to shutdown (where a hard kill would lose it).
        """
        if now is None:
            now = time.monotonic()
        for key, s in self._streams.items():
            cur_file = getattr(self, s['file'])
            try:
                size = os.path.getsize(cur_file) if os.path.exists(cur_file) else 0
            except OSError:
                size = 0
            buf = getattr(self, s['buf'], None)
            buffered = len(buf) if buf else 0
            # Nothing on disk and nothing buffered -> genuinely empty, skip.
            if size <= 0 and buffered == 0:
                continue
            age = now - self._stream_opened.get(key, now)
            if size >= self.max_file_bytes or age >= self.max_file_age:
                self._rotate_stream(key)

    def force_flush(self):
        """Flush all buffers and compress all output files."""
        # Make sure every buffer is on disk and all handles are closed before we
        # compress. _cleanup normally does this, but it is bypassed on the
        # unhandled-exception exit path in IOTracer.trace(); without this we
        # would compress files that are missing buffered rows or still hold an
        # open descriptor. Both calls are idempotent when _cleanup already ran.
        self.write_to_disk()
        self.close_handles()

        self.compress_log(self.output_block_file)
        self.compress_log(self.output_vfs_file)
        self.compress_log(self.output_cache_file)
        
        # Skip process snapshot if session is active (incomplete snapshot)
        if not self.process_snapshot_session_active:
            self.compress_log(self.output_process_file)
        else:
            logger("warning", "Skipping incomplete process snapshot upload (snapshot in progress)")
            # Clear incomplete process snapshot buffer
            self.process_buffer.clear()
        
        # Skip filesystem snapshot if session is active (incomplete snapshot)
        if not self.fs_snapshot_session_active:
            self.compress_log(self.output_fs_snapshot_file)
        else:
            logger("warning", "Skipping incomplete filesystem snapshot upload (snapshot in progress)")
            # Delete incomplete snapshot part files from disk
            for part_file in self.fs_snapshot_parts_pending_upload:
                try:
                    if os.path.exists(part_file):
                        os.remove(part_file)
                        logger("info", f"Removed incomplete snapshot part: {os.path.basename(part_file)}")
                except Exception as e:
                    logger("error", f"Failed to remove incomplete snapshot part {part_file}: {e}")
            # Clear incomplete snapshot parts and buffer
            self.fs_snapshot_parts_pending_upload.clear()
            self.fs_snap_buffer.clear()
        
        self.compress_log(self.output_nw_conn_file)
        self.compress_log(self.output_nw_sockopt_file)
        self.compress_log(self.output_nw_drop_file)

        # In automatic_upload mode every compressed log has already been queued
        # for individual upload (preserving its subdirectory) and the background
        # worker is concurrently deleting those .zst files as it uploads them.
        # Tarring the whole directory here would (a) upload every file a second
        # time inside the bundle and (b) race the worker's deletions while
        # tarfile walks the tree. Only bundle into a single tar.zst for the
        # local (non-upload) case.
        if not self.automatic_upload:
            self.compress_dir(self.output_dir)


    def _write_buffer_to_file(self, buffer, file_handle, buffer_name: str):
        """
        Write buffer contents to a file handle.
        
        Args:
            buffer: Deque containing log entries
            file_handle: Open file handle to write to
            buffer_name: Name for error logging
        """
        if not buffer:
            return

        # Drain the buffer into a local batch first, then write. We advance
        # rows_written (the manifest's "rows persisted" counter) ONLY after the
        # write+flush succeed, and we put the batch back on failure — so a write
        # error (ENOSPC / EDQUOT / a handle closed by a concurrent shutdown)
        # neither silently drops rows nor over-reports them as written. The old
        # code popped every row and bumped the counter *before* writing, so any
        # write error lost the whole batch while the manifest still counted it.
        drained = []
        while buffer:
            drained.append(buffer.popleft())
        if not drained:
            return
        complete_data = "".join(event + "\n" for event in drained)

        try:
            file_handle.write(complete_data)
            file_handle.flush()
        except Exception as e:
            # Re-queue the un-persisted rows at the FRONT (preserving order) so
            # the next periodic flush / shutdown force_flush retries them. Bound
            # the retained rows so a persistently full/over-quota disk can't grow
            # the buffers without limit; oldest rows past the cap are dropped and
            # recorded in write_dropped (honest loss, not a silent drop).
            buffer.extendleft(reversed(drained))
            dropped = 0
            while len(buffer) > self._max_buffered_rows_on_error:
                buffer.popleft()
                dropped += 1
            if dropped:
                self.write_dropped[buffer_name] = (
                    self.write_dropped.get(buffer_name, 0) + dropped
                )
            logger("error", f"Error writing {buffer_name} buffer: {e}"
                   + (f" — dropped {dropped} rows past retry cap" if dropped else ""))
            return

        self.rows_written[buffer_name] = (
            self.rows_written.get(buffer_name, 0) + len(drained)
        )

    def write_to_disk(self):
        """Write all buffered data to disk using parallel threads."""
        def write_vfs():
            with self._stream_locks['vfs']:
                if self.vfs_buffer:
                    if self._vfs_handle is None:
                        self._vfs_handle = self._open_log_file(self.output_vfs_file, 'vfs')
                    self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")

        def write_block():
            with self._stream_locks['block']:
                if self.block_buffer:
                    if self._block_handle is None:
                        self._block_handle = self._open_log_file(self.output_block_file, 'block')
                    self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")

        def write_cache():
            with self._stream_locks['cache']:
                if self.cache_buffer:
                    if self._cache_handle is None:
                        self._cache_handle = self._open_log_file(self.output_cache_file, 'cache')
                    self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")

        def write_process():
            with self._stream_locks['process']:
                if self.process_buffer:
                    if self._process_handle is None:
                        self._process_handle = self._open_log_file(self.output_process_file, 'process')
                    self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")

        def write_fssnap():
            with self._stream_locks['fs_snap']:
                if self.fs_snap_buffer:
                    if self._fs_snap_handle is None:
                        self._fs_snap_handle = self._open_log_file(self.output_fs_snapshot_file, 'fs_snap')
                    self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")

        def write_network():
            # Land any buffered network rows into their current files. Each stream
            # is keyed in the generic _streams registry, so reuse it.
            for key, label in (('nw_conn', 'NetConn'),
                               ('nw_sockopt', 'NetSockopt'), ('nw_drop', 'NetDrop')):
                s = self._streams[key]
                with self._stream_locks[key]:
                    buf = getattr(self, s['buf'])
                    if buf:
                        handle = getattr(self, s['handle'])
                        if handle is None:
                            handle = self._open_log_file(getattr(self, s['file']), key)
                            setattr(self, s['handle'], handle)
                        self._write_buffer_to_file(buf, handle, label)

        threads = []
        
        # Start parallel write threads for each buffer
        if self.vfs_buffer:
            t1 = threading.Thread(target=write_vfs)
            threads.append(t1)
            t1.start()

        if self.block_buffer:
            t2 = threading.Thread(target=write_block)
            threads.append(t2)
            t2.start()

        if self.cache_buffer:
            t3 = threading.Thread(target=write_cache)
            threads.append(t3)
            t3.start()

        if self.process_buffer:
            t4 = threading.Thread(target=write_process)
            threads.append(t4)
            t4.start()

        if self.fs_snap_buffer: 
            t5 = threading.Thread(target=write_fssnap)
            threads.append(t5)
            t5.start()

        if (self.nw_conn_buffer
                or self.nw_sockopt_buffer or self.nw_drop_buffer):
            t8 = threading.Thread(target=write_network)
            threads.append(t8)
            t8.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # NOTE: do NOT clear_events() here. Each write_*() above already drained
        # its buffer (popleft under the stream lock). A blanket buffer.clear()
        # would additionally wipe rows appended by the lock-free append_*() path
        # in the window between a stream's drain and the clear — silently losing
        # events on every periodic flush. The drain is the only emptying needed.

    def _bump_created_files(self, n: int = 1) -> int:
        """Atomically add ``n`` to the created-files counter and return the new
        total. Called from multiple threads (perf-callback / periodic-flush
        compression and the snapshot upload), where a bare ``+=`` could lose
        increments to a read-modify-write race."""
        with self._created_files_lock:
            self.created_files += n
            return self.created_files

    def compress_log(self, input_file: str):
        """
        Compress a log file and optionally upload it.

        Prefers Zstandard (.zst) and falls back to gzip (.gz) when the optional
        ``zstandard`` library is unavailable, so trace logs are always
        compressed rather than uploaded raw.

        Args:
            input_file: Path to the file to compress
        """
        try:
            src = input_file

            # Check if file exists (may already be compressed for multi-part files)
            if not os.path.exists(src):
                return

            compressed = compress_file(src)
            # If compression somehow failed, fall back to the uncompressed file
            # so trace data is still uploaded rather than lost.
            upload_target = compressed if compressed is not None else src

            if self.automatic_upload:
                total_created = self._bump_created_files()
                logger('info', f"Files Created: {str(total_created)}", True)
                # Upload each log individually, preserving its subdirectory
                # (fs, block, cache, process, ...) on the backend.
                self.upload_manager.append_object(upload_target)
            if compressed is not None and compressed != src:
                os.remove(src)
        except Exception as e:
            logger("error", f"Failed compressing log {input_file}: {e}")
            
    def compress_dir(self, input_dir: str):
        """
        Compress a directory to a tar bundle and optionally upload.

        Prefers Zstandard (.tar.zst) and falls back to gzip (.tar.gz) when the
        optional ``zstandard`` library is unavailable, so the bundle is still
        compressed rather than left as a plain tar.

        Args:
            input_dir: Path to the directory to compress
        """
        try:
            src = input_dir
            base = input_dir.rstrip("/").rstrip("\\")

            zstandard = zstandard_available()
            if zstandard is not None:
                dst = base + ".tar.zst"
                cctx = zstandard.ZstdCompressor(level=ZSTD_LEVEL)
                with open(dst, "wb") as f_out:
                    with cctx.stream_writer(f_out) as compressor:
                        with tarfile.open(mode="w|", fileobj=compressor) as tar:
                            tar.add(src, arcname=os.path.basename(src))
            else:
                # gzip fallback — always available in the standard library.
                dst = base + ".tar.gz"
                with tarfile.open(dst, mode="w:gz", compresslevel=GZIP_LEVEL) as tar:
                    tar.add(src, arcname=os.path.basename(src))

            if self.automatic_upload:
                total_created = self._bump_created_files()
                logger("info", f"Files Created: {total_created}", True)
                self.upload_manager.append_object(dst)

            shutil.rmtree(src)

        except Exception as e:
            logger("error", f"Failed compressing directory {input_dir}: {e}")
        

    def close_handles(self):
        """Close all open file handles and stop background threads."""
        # Stop periodic flush thread
        self._periodic_flush_active = False
        
        handles = [
            (self._vfs_handle, "VFS"),
            (self._block_handle, "Block"), 
            (self._cache_handle, "Cache"),
            (self._process_handle, "Process State"),
            (self._fs_snap_handle, "Filesystem Snapshot"),
            (self._nw_conn_handle, "NetConn"),
            (self._nw_sockopt_handle, "NetSockopt"),
            (self._nw_drop_handle, "NetDrop"),
        ]

        for handle, name in handles:
            if handle:
                try:
                    handle.flush()
                    handle.close()
                    # logger("info", f"Closed {name} file handle")
                except Exception as e:
                    logger("error", f"Error closing {name} handle: {e}")

        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._process_handle = None
        self._fs_snap_handle = None
        self._nw_conn_handle = None
        self._nw_sockopt_handle = None
        self._nw_drop_handle = None
