"""
ObjectStorageManager - Handles uploading trace files to cloud storage.

This module provides the ObjectStorageManager class which manages:
- Connection testing to the backend storage service
- Getting presigned URLs for file uploads
- Uploading individual files
- Background upload workers with retry logic

The manager supports both manual and automatic upload modes,
with automatic upload using a background thread and queue system.

Example:
    manager = ObjectStorageManager(version="vRelease")
    manager.test_connection()  # Check if server is reachable
    manager.put_object("/path/to/trace.tar.zst")  # Upload a file
"""

import mimetypes
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
import requests

from src.utility.utils import capture_machine_id, logger, get_current_tag, unlock_reward, run_with_spinner


class ObjectStorageManager:
    """
    Manages object storage operations for trace file uploads.
    
    This class handles:
    - Testing connectivity to the backend storage
    - Obtaining presigned upload URLs
    - Uploading trace files with retry and backoff
    - Background upload worker management
    
    Attributes:
        backend_url: Base URL for the storage backend
        machine_id: Unique identifier for this machine
        current_datetime: Timestamp for this session
        file_queue: Queue of files pending upload
        successful_upload: Count of successful uploads
        app_version: Version string for this application
        
    Attributes:
        _stop: Threading Event to signal worker shutdown
        _t: List of worker threads
    """
    
    def __init__(self, version: str = "vdev", trace_bucket: str = "linux_v1"):
        """
        Initialize the ObjectStorageManager.

        Args:
            version: Application version string (default: "vdev")
            trace_bucket: Storage bucket/path prefix for uploads (default: "linux_v1")

        Initializes the upload queue, counters, and prepares
        for automatic upload operations.
        """
        self._stop = threading.Event()
        self._t: list[threading.Thread] = []
        self.backend_url = "https://io-tracer-worker.1a1a11a.workers.dev"
        # self.app_version = get_current_tag()
        self.machine_id = capture_machine_id()
        self.current_datetime = datetime.now()
        self.file_queue: Queue[str] = Queue()
        self.successful_upload = 0
        self.app_version = version
        self.trace_bucket = trace_bucket
        # Per-file upload attempt counts. A permanently-failing ("poison") shard
        # is dropped after MAX_UPLOAD_ATTEMPTS instead of being requeued forever
        # — an unbounded requeue both hot-spins the worker and prevents
        # clean_queue()/stop_worker() from ever draining the queue.
        self._attempts: dict[str, int] = {}
        self.MAX_UPLOAD_ATTEMPTS = 5


    def test_connection(self) -> bool:
        """
        Test connectivity to the backend storage server.

        Returns:
            bool: True if connection successful, False otherwise
        """
        def _check():
            r = requests.get(f"{self.backend_url}/connection-test.txt", timeout=5)
            if not r.ok:
                raise Exception("can't connect")
            return True

        try:
            result = run_with_spinner("Testing connection", _check)
            return result
        except Exception:
            logger("warn", "Unable to reach remote object storage server.")
            logger("info", "saving traces locally")
            return False

    def get_presigned_url(self, filename: str, file_type: str) -> str:
        """
        Get a presigned URL for uploading a file.
        
        Args:
            filename: Name of the file to upload
            file_type: Type/category of the file (e.g., "fs", "block", "process")
            
        Returns:
            str: Presigned URL for the upload request
            
        Raises:
            RuntimeError: If the request fails
        """
        r = requests.post(
            f"{self.backend_url}/{self.trace_bucket}/"
            f"{self.machine_id.upper()}/"
            f"{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}/"
            f"{file_type}/"
            f"{filename}",
            timeout=10,
        )
        if not r.ok:
            raise RuntimeError(f"Failed to get presign: {r.status_code} {r.text}")
        return r.text

    def put_object(self, file_path: str):
        """
        Upload a single file to cloud storage.
        
        Gets a presigned URL for the file, then uploads it using
        an HTTP PUT request with appropriate content type.
        
        Args:
            file_path: Path to the file to upload
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            RuntimeError: If upload fails
            
        Side Effects:
            - Removes the local file after successful upload
            - Increments successful_upload counter
            - Unlocks reward if applicable
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Not a file: {path}")

        presigned_url = self.get_presigned_url(filename=path.name, file_type = path.parts[-2])
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        with path.open("rb") as f:
            r = requests.put(
                presigned_url,
                data=f,
                headers={"Content-Type": content_type},
                timeout=10,
            )
        if r.ok:
            os.remove(file_path)
            self.successful_upload += 1
            unlock_reward()  
            logger("info", f"Files Uploaded: {self.successful_upload}", True)
        else:
            raise RuntimeError(f"Upload failed: {r.status_code} {r.text}")

    def append_object(self, file_path: str):
        """
        Add a file to the upload queue.
        
        Args:
            file_path: Path to the file to queue for upload
        """
        self.file_queue.put(file_path)

    def _automatic_upload_worker(self):
        """
        Background worker that processes the upload queue.
        
        This method runs in a separate thread, continuously checking
        the file queue and uploading files. It implements exponential
        backoff on repeated failures.
        
        The worker exits when _stop event is set or the queue is empty
        (with timeout).
        """
        backoff = 1
        while True:
            if self._stop.is_set():
                break

            try:
                fp = self.file_queue.get(timeout=0.5)
            except Empty:
                continue

            try:
                self.put_object(fp)
                backoff = 1  # Reset backoff after success
                self._attempts.pop(fp, None)
            except FileNotFoundError as e:
                # File was already uploaded and deleted, don't requeue
                logger("debug", f"File already uploaded: {str(e)}")
                self._attempts.pop(fp, None)
            except Exception as e:
                attempts = self._attempts.get(fp, 0) + 1
                self._attempts[fp] = attempts
                if attempts >= self.MAX_UPLOAD_ATTEMPTS:
                    # Give up on this shard rather than requeue forever (which
                    # would spin the worker and block queue drain on shutdown).
                    # The local file is left on disk for a later manual retry.
                    self._attempts.pop(fp, None)
                    logger("error",
                           f"Upload of {fp} failed {attempts} times; giving up "
                           f"(kept locally): {str(e)}")
                else:
                    logger("warn",
                           f"Upload error ({attempts}/{self.MAX_UPLOAD_ATTEMPTS}): "
                           f"{str(e)}. Requeueing.")
                    self.file_queue.put(fp)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 10)
            finally:
                self.file_queue.task_done()

    def start_worker(self, daemon: bool = False, num_workers: int = 1):
        """
        Start the background upload worker(s).
        
        Args:
            daemon: Whether to run workers as daemon threads (default: False)
            num_workers: Number of worker threads to start (default: 1)
        """
        if self._t and any(t.is_alive() for t in self._t):
            return
        logger("info", f"Starting {num_workers} uploader workers")
        self._stop.clear()
        self._t = [
            threading.Thread(target=self._automatic_upload_worker, daemon=daemon)
            for _ in range(num_workers)
        ]
        for t in self._t:
            t.start()

    def clean_queue(self, timeout: float | None = None) -> bool:
        """
        Wait for the upload queue to be fully processed.
        
        Args:
            timeout: Maximum time to wait in seconds (None for unlimited)
            
        Returns:
            bool: True if queue was drained, False if timeout occurred
        """
        start = time.time()
        while True:
            if self.file_queue.unfinished_tasks == 0:
                return True

            if timeout is not None and (time.time() - start) >= timeout:
                return False

            time.sleep(0.1)


    def stop_worker(self, server_mode: bool, timeout: float | None = 10):
        """
        Stop all upload workers.
        
        Args:
            server_mode: If True, wait for queue to drain before stopping
            timeout: Maximum time to wait for pending uploads
        """
        logger("info", "Flushing pending uploads")

        if server_mode:
            drained = self.clean_queue(timeout=timeout)
            if not drained:
                logger("warn", "Timeout while waiting for uploads to finish. Some files may remain in the queue.")

        self._stop.set()

        for t in self._t:
            if t:
                t.join(timeout=timeout)
        self._t = []

