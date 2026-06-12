"""
WriterManager - Manages writing trace data to files with buffering and compression.

This module provides the WriteManager class which handles:
- Creating output directory structure
- Buffering trace events for different subsystems
- Writing events to CSV files
- Compressing output files with gzip
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
import io
from datetime import datetime
import tarfile

from .ObjectStorageManager import ObjectStorageManager
from ..utility.utils import logger, create_tar_gz, capture_machine_id, compress_log
import threading
from collections import deque
import gzip
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
        ds/*.csv: Block device traces
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
        self.last_status_log_time = time.time()
        self.status_log_interval = 60  # Log status every 60 seconds
        self.output_dir = output_dir
        self.output_vfs_file = f"{self.output_dir}/fs/fs_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_block_file = f"{self.output_dir}/ds/ds_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_cache_file = f"{self.output_dir}/cache/cache_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_fs_snapshot_file = f"{self.output_dir}/filesystem_snapshot/filesystem_snapshot_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_pagefault_file = f"{self.output_dir}/pagefault/pagefault_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"
        self.output_io_uring_file = f"{self.output_dir}/io_uring/io_uring_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

        # Create output directories
        os.makedirs(f"{self.output_dir}/system_spec", exist_ok=True)
        os.makedirs(f"{self.output_dir}/fs", exist_ok=True)
        os.makedirs(f"{self.output_dir}/ds", exist_ok=True)
        os.makedirs(f"{self.output_dir}/cache", exist_ok=True)
        os.makedirs(f"{self.output_dir}/process", exist_ok=True)
        os.makedirs(f"{self.output_dir}/filesystem_snapshot", exist_ok=True)
        os.makedirs(f"{self.output_dir}/pagefault", exist_ok=True)
        os.makedirs(f"{self.output_dir}/io_uring", exist_ok=True)

        self.upload_manager = upload_manager
        self.automatic_upload = automatic_upload

        # Event buffers for each subsystem
        self.vfs_buffer = deque()
        self.block_buffer = deque()
        self.cache_buffer = deque()
        self.process_buffer = deque()
        self.fs_snap_buffer = deque()
        self.pagefault_buffer = deque()
        self.io_uring_buffer = deque()
        
        # Event rate tracking
        self.event_timestamps = {
            'vfs': deque(maxlen=1000),
            'block': deque(maxlen=1000),
            'cache': deque(maxlen=1000),
            'fs_state': deque(maxlen=1000),
            'proc_state': deque(maxlen=1000),
            'pagefault': deque(maxlen=1000),
            'io_uring': deque(maxlen=1000),
        }
        
        # Dynamic thresholds (min, max)
        self.dynamic_limits = {
            'vfs': (8000, 500000),
            'block': (8000, 50000),
            'cache': (20000, 1000000),
            'fs_state': (8000, 20000),
            'proc_state': (8000, 10000),  # Match new process_max_events threshold
            'pagefault': (8000, 100000),
            'io_uring': (8000, 200000),
        }
        
        # Start adaptive sizing thread
        self.adaptive_thread = threading.Thread(target=self._adaptive_sizing, daemon=True)
        self.adaptive_thread.start()
        
        # Start periodic flush thread (every 20 minutes)
        self._periodic_flush_active = True
        self._last_flush_time = time.time()
        self.periodic_flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self.periodic_flush_thread.start()
        

        # Buffer flush thresholds
        self.cache_max_events = 20000
        self.vfs_max_events = 8000
        self.block_max_events = 8000
        self.process_max_events = 8000  # Large enough to fit entire hourly snapshot
        self.fs_snap_max_events = 8000
        self.pagefault_max_events = 8000
        self.io_uring_max_events = 8000

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
            'pagefault': threading.Lock(),
            'io_uring':  threading.Lock(),
        }

        # File handles for each output
        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None
        self._process_handle = None
        self._pagefault_handle = None
        self._fs_snap_handle = None
        self._io_uring_handle = None

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

        # Bundle upload tracking: accumulate files and upload as a single tar
        self._pending_bundle: list[str] = []
        self._bundle_lock = threading.Lock()
        self._bundle_counter = 0
        self.bundle_size = 5

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
            
            for event_type in ['vfs', 'block', 'cache', 'fs_state','proc_state', 'pagefault', 'io_uring']:
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
                elif event_type == 'pagefault':
                    self.pagefault_max_events = new_limit
                elif event_type == 'io_uring':
                    self.io_uring_max_events = new_limit

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
        if len(self.pagefault_buffer) > 0:
            buffer_info.append(f"PgFault:{len(self.pagefault_buffer)}")
        if len(self.io_uring_buffer) > 0:
            buffer_info.append(f"IO_Uring:{len(self.io_uring_buffer)}")
        
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

    def should_flush_pagefault(self) -> bool:
        """Check if pagefault buffer should be flushed."""
        return (len(self.pagefault_buffer) >= self.pagefault_max_events)

    def should_flush_io_uring(self) -> bool:
        """Check if io_uring buffer should be flushed."""
        return (len(self.io_uring_buffer) >= self.io_uring_max_events)

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
                self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
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

    def append_pagefault_log(self, log_output: str):
        """
        Add a page fault event log entry.
        
        Args:
            log_output: CSV-formatted log string
        """
        if isinstance(log_output, str):
            self.pagefault_buffer.append(log_output)
            self.event_timestamps['pagefault'].append(time.time())

            if self.should_flush_pagefault():
                self.flush_pagefault_only()
        else:
            logger("error", "Invalid pagefault log output format. Expected a string.")

    def append_io_uring_log(self, log_output: str):
        """Add an io_uring event log entry."""
        if isinstance(log_output, str):
            self.io_uring_buffer.append(log_output)
            self.event_timestamps['io_uring'].append(time.time())
            if self.should_flush_io_uring():
                self.flush_io_uring_only()
        else:
            logger("error", "Invalid io_uring log output format. Expected a string.")

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
                self._add_to_bundle(dst)
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

            # Open file handle for this part if needed
            if self._fs_snap_handle is None or self.output_fs_snapshot_file != part_filepath:
                if self._fs_snap_handle is not None:
                    self._fs_snap_handle.close()
                self._fs_snap_handle = open(part_filepath, 'a', buffering=8192)
                self.output_fs_snapshot_file = part_filepath

            # Write buffer to file
            self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")

            # Close handle before compression
            self._fs_snap_handle.close()
            self._fs_snap_handle = None

            # Compress with gzip
            if os.path.exists(part_filepath):
                # Don't log or count each part - we'll log when snapshot is complete
                with open(part_filepath, "rb") as f_in:
                    with gzip.open(part_filepath + ".gz", "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

                os.remove(part_filepath)
                compressed_file = part_filepath + ".gz"

                # Store for later upload (after snapshot completion and final part rename)
                if self.automatic_upload:
                    self.fs_snapshot_parts_pending_upload.append(compressed_file)
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
        if not self.fs_snapshot_session_active:
            return
        
        total_parts = self.fs_snapshot_part_number - 1  # -1 because we increment after each flush
        
        if total_parts < 1:
            # No parts were written
            self.fs_snapshot_session_active = False
            return
        
        # Find the last part file (compressed)
        last_part_str = f"{total_parts:04d}"
        old_filename = (
            f"filesystem_snapshot_part{last_part_str}_"
            f"{self.fs_snapshot_timestamp}_"
            f"{self.fs_snapshot_device_id}.csv.gz"
        )
        old_filepath = f"{self.output_dir}/filesystem_snapshot/{old_filename}"
        
        # Construct new filename with completion marker
        new_filename = (
            f"filesystem_snapshot_part{last_part_str}_"
            f"{self.fs_snapshot_timestamp}_"
            f"{self.fs_snapshot_device_id}_complete_parts{total_parts}.csv.gz"
        )
        new_filepath = f"{self.output_dir}/filesystem_snapshot/{new_filename}"
        
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
                    self.created_files += num_parts
                    logger('info', f"Files Created: {str(self.created_files)} (filesystem snapshot with {num_parts} parts)", True)
                for part_file in self.fs_snapshot_parts_pending_upload:
                    if os.path.exists(part_file):
                        self._add_to_bundle(part_file)
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
        with self._stream_locks['process']:
            if self.process_buffer:
                if self._process_handle is None:
                    self._process_handle = open(self.output_process_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")
                self.compress_log(self.output_process_file)
                self.output_process_file = f"{self.output_dir}/process/process_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._process_handle.close()
                self._process_handle = open(self.output_process_file, 'a', buffering=8192)
                self._reset_flush_timer()

                # Mark process snapshot as complete
                self.process_snapshot_session_active = False
                logger("info", "Process Snapshot: completed and flushed")

    def flush_cache_only(self):
        """Flush cache buffer to file."""
        with self._stream_locks['cache']:
            if self.cache_buffer:
                if self._cache_handle is None:
                    self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")
                self.compress_log(self.output_cache_file)
                self.output_cache_file = f"{self.output_dir}/cache/cache_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._cache_handle.close()
                self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
                self._reset_flush_timer()


    def flush_vfs_only(self):
        """Flush VFS buffer to file."""
        with self._stream_locks['vfs']:
            if self.vfs_buffer:
                if self._vfs_handle is None:
                    self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")
                self.compress_log(self.output_vfs_file)
                self.output_vfs_file = f"{self.output_dir}/fs/fs_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._vfs_handle.close()
                self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
                self._reset_flush_timer()

    def flush_block_only(self):
        """Flush block buffer to file."""
        with self._stream_locks['block']:
            if self.block_buffer:
                if self._block_handle is None:
                    self._block_handle = open(self.output_block_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")
                self.compress_log(self.output_block_file)
                self.output_block_file = f"{self.output_dir}/ds/ds_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._block_handle.close()
                self._block_handle = open(self.output_block_file, 'a', buffering=8192)
                self._reset_flush_timer()

    def flush_pagefault_only(self):
        """Flush pagefault buffer to file."""
        with self._stream_locks['pagefault']:
            if self.pagefault_buffer:
                if self._pagefault_handle is None:
                    self._pagefault_handle = open(self.output_pagefault_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.pagefault_buffer, self._pagefault_handle, "PageFault")
                self.compress_log(self.output_pagefault_file)
                self.output_pagefault_file = f"{self.output_dir}/pagefault/pagefault_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._pagefault_handle.close()
                self._pagefault_handle = open(self.output_pagefault_file, 'a', buffering=8192)
                self._reset_flush_timer()

    def flush_io_uring_only(self):
        """Flush io_uring buffer to file."""
        with self._stream_locks['io_uring']:
            if self.io_uring_buffer:
                if self._io_uring_handle is None:
                    self._io_uring_handle = open(self.output_io_uring_file, 'a', buffering=8192)
                self.current_datetime = datetime.now()

                self._write_buffer_to_file(self.io_uring_buffer, self._io_uring_handle, "IO_Uring")
                self.compress_log(self.output_io_uring_file)
                self.output_io_uring_file = f"{self.output_dir}/io_uring/io_uring_{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}.csv"

                self._io_uring_handle.close()
                self._io_uring_handle = open(self.output_io_uring_file, 'a', buffering=8192)
                self._reset_flush_timer()

    def force_flush(self):
        """Flush all buffers and compress all output files."""
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
        
        self.compress_log(self.output_pagefault_file)
        self.compress_log(self.output_io_uring_file)
        if self.automatic_upload:
            self._flush_bundle()
        self.compress_dir(self.output_dir)


    def clear_events(self):
        """Clear all event buffers."""
        print("Clear initiated")
        self.vfs_buffer.clear()
        self.block_buffer.clear() 
        self.cache_buffer.clear()
        self.process_buffer.clear()
        self.fs_snap_buffer.clear()
        self.pagefault_buffer.clear()
        self.io_uring_buffer.clear()

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
            
        try:
            string_buffer = io.StringIO()
            
            while buffer:
                event = buffer.popleft()
                string_buffer.write(event)
                string_buffer.write('\n')
            
            complete_data = string_buffer.getvalue()
            file_handle.write(complete_data)
            file_handle.flush()
            
            string_buffer.close()
            
        except Exception as e:
            logger("error", f"Error writing {buffer_name} buffer: {e}")

    def write_to_disk(self):
        """Write all buffered data to disk using parallel threads."""
        def write_vfs():
            with self._stream_locks['vfs']:
                if self.vfs_buffer:
                    if self._vfs_handle is None:
                        self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.vfs_buffer, self._vfs_handle, "VFS")

        def write_block():
            with self._stream_locks['block']:
                if self.block_buffer:
                    if self._block_handle is None:
                        self._block_handle = open(self.output_block_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.block_buffer, self._block_handle, "Block")

        def write_cache():
            with self._stream_locks['cache']:
                if self.cache_buffer:
                    if self._cache_handle is None:
                        self._cache_handle = open(self.output_cache_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.cache_buffer, self._cache_handle, "Cache")

        def write_process():
            with self._stream_locks['process']:
                if self.process_buffer:
                    if self._process_handle is None:
                        self._process_handle = open(self.output_process_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.process_buffer, self._process_handle, "Process State")

        def write_fssnap():
            with self._stream_locks['fs_snap']:
                if self.fs_snap_buffer:
                    if self._fs_snap_handle is None:
                        self._fs_snap_handle = open(self.output_fs_snapshot_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.fs_snap_buffer, self._fs_snap_handle, "Filesystem Snapshot")

        def write_pagefault():
            with self._stream_locks['pagefault']:
                if self.pagefault_buffer:
                    if self._pagefault_handle is None:
                        self._pagefault_handle = open(self.output_pagefault_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.pagefault_buffer, self._pagefault_handle, "PageFault")

        def write_io_uring():
            with self._stream_locks['io_uring']:
                if self.io_uring_buffer:
                    if self._io_uring_handle is None:
                        self._io_uring_handle = open(self.output_io_uring_file, 'a', buffering=8192)
                    self._write_buffer_to_file(self.io_uring_buffer, self._io_uring_handle, "IO_Uring")

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

        if self.pagefault_buffer:
            t7 = threading.Thread(target=write_pagefault)
            threads.append(t7)
            t7.start()

        if self.io_uring_buffer:
            t13 = threading.Thread(target=write_io_uring)
            threads.append(t13)
            t13.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        self.clear_events()

    def _add_to_bundle(self, file_path: str):
        """Queue a compressed file for bundled upload."""
        with self._bundle_lock:
            self._pending_bundle.append(file_path)
            should_flush = len(self._pending_bundle) >= self.bundle_size
        if should_flush:
            self._flush_bundle()

    def _flush_bundle(self):
        """Pack all pending files into one tar and queue it for upload."""
        with self._bundle_lock:
            if not self._pending_bundle:
                return
            files_to_bundle = list(self._pending_bundle)
            self._pending_bundle.clear()
            self._bundle_counter += 1
            counter = self._bundle_counter

        bundle_dir = os.path.dirname(self.output_dir.rstrip("/\\"))
        bundle_ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        bundle_path = os.path.join(bundle_dir, f"bundle_{counter:04d}_{bundle_ts}.tar")

        try:
            with tarfile.open(bundle_path, "w") as tar:
                for f in files_to_bundle:
                    if os.path.exists(f):
                        tar.add(f, arcname=os.path.relpath(f, bundle_dir))
            # Tar closed successfully — safe to delete sources now
            for f in files_to_bundle:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except OSError as rm_err:
                        logger("warning", f"Failed to remove bundled file {f}: {rm_err}")
            self.upload_manager.append_object(bundle_path)
        except Exception as e:
            logger("error", f"Failed to create upload bundle: {e}")
            if os.path.exists(bundle_path):
                try:
                    os.remove(bundle_path)
                except OSError:
                    pass
            for f in files_to_bundle:
                if os.path.exists(f):
                    self.upload_manager.append_object(f)

    def compress_log(self, input_file: str):
        """
        Compress a log file with gzip and optionally upload.
        
        Args:
            input_file: Path to the file to compress
        """
        try:
            src = input_file
            dst = input_file + ".gz"
            
            # Check if file exists (may already be compressed for multi-part files)
            if not os.path.exists(src):
                return
            
            with open(src, "rb") as f_in:
                with gzip.open(dst, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out) # type: ignore

            if self.automatic_upload:
                self.created_files += 1
                logger('info', f"Files Created: {str(self.created_files)}", True)
                self._add_to_bundle(dst)
            os.remove(src)
        except Exception as e:
            logger("error", f"Failed compressing log {input_file}: {e}")
            
    def compress_dir(self, input_dir: str):
        """
        Compress a directory to tar.gz and optionally upload.
        
        Args:
            input_dir: Path to the directory to compress
        """
        try:
            src = input_dir
            dst = input_dir.rstrip("/").rstrip("\\") + ".tar.gz"

            with tarfile.open(dst, "w:gz") as tar:
                tar.add(src, arcname=os.path.basename(src))

            if self.automatic_upload:
                self.created_files += 1
                logger("info", f"Files Created: {self.created_files}", True)
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
            (self._pagefault_handle, "PageFault"),
            (self._io_uring_handle, "IO_Uring"),
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
        self._pagefault_handle = None
        self._io_uring_handle = None
