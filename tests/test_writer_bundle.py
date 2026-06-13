"""
Unit tests for WriteManager's local bundle buffering.

These exercise the size/age based bundling logic that buffers compressed
trace files locally and only merges them into a single tar for upload once
100 MB has accumulated or 20 minutes have elapsed. They use a fake upload
manager so no network or kernel access is required.

Run via either:
    python3 -m unittest discover -s tests
    pytest tests/
"""

import os
import sys
import tarfile
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer.WriterManager import WriteManager


class FakeUploadManager:
    """Minimal stand-in that records what would be uploaded."""

    def __init__(self):
        self.uploaded = []

    def append_object(self, file_path):
        self.uploaded.append(file_path)


class BundleBufferingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = WriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )
        # Stop the background threads so they don't interfere with assertions.
        self.wm._periodic_flush_active = False

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_file(self, name, size):
        path = os.path.join(self.output_dir, "fs", name)
        with open(path, "wb") as f:
            f.write(b"\0" * size)
        return path

    def test_under_size_threshold_does_not_flush(self):
        self.wm.bundle_max_bytes = 1000
        f = self._make_file("a.csv.gz", 100)
        self.wm._add_to_bundle(f)

        self.assertEqual(self.wm._pending_bundle, [f])
        self.assertEqual(self.wm._pending_bundle_bytes, 100)
        self.assertEqual(self.upload.uploaded, [])

    def test_size_threshold_triggers_merge_and_upload(self):
        self.wm.bundle_max_bytes = 250
        files = [self._make_file(f"f{i}.csv.gz", 100) for i in range(3)]
        for f in files:
            self.wm._add_to_bundle(f)

        # Crossing 250 bytes (after the third 100-byte file) should flush.
        self.assertEqual(len(self.upload.uploaded), 1)
        bundle_path = self.upload.uploaded[0]
        self.assertTrue(bundle_path.endswith(".tar"))
        self.assertTrue(os.path.exists(bundle_path))

        # Buffer is reset and the merged source files are removed from disk.
        self.assertEqual(self.wm._pending_bundle, [])
        self.assertEqual(self.wm._pending_bundle_bytes, 0)
        for f in files:
            self.assertFalse(os.path.exists(f))

        # All three files made it into the merged tar.
        with tarfile.open(bundle_path) as tar:
            self.assertEqual(len(tar.getmembers()), 3)

    def test_window_start_resets_on_new_buffer(self):
        self.wm.bundle_max_bytes = 10_000
        old = time.time() - 9999
        self.wm._bundle_window_start = old

        f = self._make_file("a.csv.gz", 10)
        self.wm._add_to_bundle(f)

        # First file of an empty buffer should restart the age clock.
        self.assertGreater(self.wm._bundle_window_start, old)

    def test_flush_resets_counters(self):
        self.wm.bundle_max_bytes = 10_000
        f = self._make_file("a.csv.gz", 500)
        self.wm._add_to_bundle(f)
        self.assertEqual(self.wm._pending_bundle_bytes, 500)

        self.wm._flush_bundle()

        self.assertEqual(self.wm._pending_bundle, [])
        self.assertEqual(self.wm._pending_bundle_bytes, 0)
        self.assertEqual(len(self.upload.uploaded), 1)


if __name__ == "__main__":
    unittest.main()
