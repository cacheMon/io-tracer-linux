"""
ProcessSnapper - Captures process state snapshots during tracing.

This module provides the ProcessSnapper class which periodically captures
information about running processes, including:
- Process ID (PID) and name
- Memory usage (RSS, VMS)
- Command line
- Creation time and status
- CPU utilization over various intervals

Example:
    snapper = ProcessSnapper(writer_manager=wm, anonymous=False)
    snapper.run()  # Start snapshot thread
    snapper.stop_snapper()  # Stop the snapper
"""

from datetime import datetime

from .sampler.ProcessSampler import ProcessSampler
from ...utility.utils import format_csv_row, logger, compress_log, simple_hash
from ..WriterManager import WriteManager
import psutil
import time
import threading


class ProcessSnapper:
    """
    Captures periodic snapshots of running processes.
    
    This class iterates through all running processes at regular intervals
    and records their state, including memory usage, command line, and
    CPU utilization. The data provides context about which processes
    were active during the trace.
    
    Attributes:
        wm: WriteManager for outputting snapshot data
        processes: List of process information
        anonymous: Whether to anonymize process names/command lines
        sampler: ProcessSampler for CPU utilization data
        running: Flag controlling the snapshot loop
        
    Example:
        snapper = ProcessSnapper(wm, anonymous=True)
        snapper.run()
        # ... later ...
        snapper.stop_snapper()
    """
    
    def __init__(self, wm: WriteManager, anonymous: bool):
        """
        Initialize the ProcessSnapper.
        
        Args:
            wm: WriteManager for outputting snapshot data
            anonymous: Whether to anonymize process information
        """
        self.wm = wm
        self.processes = []
        self.anonymous = anonymous
        
        self.sampler = ProcessSampler()
        self.sampler.start()
        self.running = True

    def stop_snapper(self):
        """Stop the snapshot thread and sampler."""
        self.running = False
        self.sampler.stop()

    def _take_snapshot(self):
        """
        Capture a single process snapshot.
        
        Iterates through all running processes, collecting process
        information and CPU utilization data. Flushes immediately
        after completion to ensure one snapshot = one file.
        
        Returns:
            bool: True if snapshot completed, False if interrupted
        """
        # Mark snapshot session as active
        self.wm.start_process_snapshot_session()
        
        # Millisecond resolution so snapshot rows can be ordered within a second.
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        for proc in psutil.process_iter(['pid', 'name', 'memory_info','cmdline','create_time','status']):
            # Check if stop was requested during iteration
            if not self.running:
                # Snapshot was interrupted - don't flush or mark complete
                return False
                
            try:
                ts = timestamp
                pid = proc.info['pid']
                name = proc.info['name'] or ''
                working_set_size = proc.info['memory_info'].rss / 1024 
                virtual_mem = proc.info['memory_info'].vms / 1024
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if self.anonymous:
                    cmdline = simple_hash(cmdline, length=12)
                create_time = float(proc.info['create_time'])
                status = proc.info.get('status','')


                cpu_5s = self.sampler.cpu_percent_for_interval(pid, create_time, 5.0) or 0.0
                cpu_2m = self.sampler.cpu_percent_for_interval(pid, create_time, 120.0) or 0.0
                cpu_1h = self.sampler.cpu_percent_for_interval(pid, create_time, 3600.0) or 0.0

                out = format_csv_row(ts, pid, name, cmdline, virtual_mem, working_set_size, datetime.fromtimestamp(create_time), cpu_5s, cpu_2m, cpu_1h, status)
                
                self.wm.append_process_log(out)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                # Expected errors while iterating over system processes; skip this process.
                logger("info", f"Skipping process {getattr(proc, 'pid', 'unknown')} due to psutil error: {e}")
            except Exception as e:
                # Log unexpected errors to avoid silently hiding issues in the snapshot loop.
                logger("warning", f"Unexpected error while collecting process snapshot data: {e}")
        
        # Check one final time before flushing
        if not self.running:
            return False
            
        # Flush immediately after snapshot completes to ensure one snapshot = one file
        self.wm.flush_process_state_only()
        return True

    def process_snapshot(self):
        """
        Main loop for capturing process snapshots every 5 minutes.
        
        Iterates through all running processes every 5 minutes,
        collecting process information and CPU utilization data.
        """
        last_snapshot_time = None
        
        while self.running:
            current_time = time.time()
            
            # Check if we should take a snapshot
            if last_snapshot_time is None:
                # First snapshot - run immediately
                completed = self._take_snapshot()
                if completed:
                    last_snapshot_time = time.time()
            else:
                # Check if 5 minutes have passed since last snapshot
                time_since_last_snapshot = current_time - last_snapshot_time
                if time_since_last_snapshot >= 300:  # 300 seconds = 5 minutes
                    completed = self._take_snapshot()
                    if completed:
                        last_snapshot_time = time.time()
                else:
                    # Less than 5 minutes ago - sleep 1 minute
                    time.sleep(60)

    def run(self):
        """Start the process snapshot in a background daemon thread."""
        snapper_thread = threading.Thread(target=self.process_snapshot)
        snapper_thread.daemon = True
        snapper_thread.start()
