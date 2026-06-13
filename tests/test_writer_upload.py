"""
Unit tests for WriteManager's per-file upload behavior.

Trace logs are uploaded individually (no tar bundling), each under its own
subdirectory (fs, ds, cache, process, ...), and the per-stream flush
thresholds are sized so each rotated log is large. These tests use a fake
upload manager so no network or kernel access is required.

Run via either:
    python3 -m unittest discover -s tests
    pytest tests/
"""

import gzip
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# WriterManager imports ObjectStorageManager, which imports `requests` at module
# load time. These tests never touch the network, and minimal CI environments do
# not install `requests`, so fall back to a stub module when it is unavailable.
if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["requests"] = types.ModuleType("requests")

from src.tracer.WriterManager import WriteManager


class FakeUploadManager:
    """Minimal stand-in that records what would be uploaded."""

    def __init__(self):
        self.uploaded = []

    def append_object(self, file_path):
        self.uploaded.append(file_path)


class SilentWriteManager(WriteManager):
    """WriteManager with its background threads neutered for tests.

    ``__init__`` still spins up the adaptive-sizing and periodic-flush threads,
    but overriding their targets with no-ops makes them exit immediately so
    they neither linger across test runs nor fire timers during assertions.
    """

    def _adaptive_sizing(self):
        return

    def _periodic_flush(self):
        return


class PerFileUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_log(self, subdir, name, text):
        path = os.path.join(self.output_dir, subdir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_compress_log_uploads_individual_gz(self):
        src = self._make_log("fs", "fs_x.csv", "a,b,c\n1,2,3\n")
        self.wm.compress_log(src)

        # Exactly one upload, the compressed file — no tar bundle.
        self.assertEqual(len(self.upload.uploaded), 1)
        uploaded = self.upload.uploaded[0]
        self.assertTrue(uploaded.endswith(".csv.gz"))
        self.assertFalse(uploaded.endswith(".tar"))
        self.assertTrue(os.path.exists(uploaded))
        # Source .csv is removed once compressed.
        self.assertFalse(os.path.exists(src))
        # Content round-trips through gzip.
        with gzip.open(uploaded, "rt") as f:
            self.assertEqual(f.read(), "a,b,c\n1,2,3\n")

    def test_upload_preserves_subdirectory(self):
        # The backend file_type is derived from the parent directory, so each
        # stream must stay under its own subdir (fs, ds, cache, ...).
        for subdir in ("fs", "ds", "cache", "process"):
            src = self._make_log(subdir, f"{subdir}_x.csv", "row\n")
            self.wm.compress_log(src)

        self.assertEqual(len(self.upload.uploaded), 4)
        parents = {os.path.basename(os.path.dirname(p)) for p in self.upload.uploaded}
        self.assertEqual(parents, {"fs", "ds", "cache", "process"})

    def test_no_upload_when_automatic_disabled(self):
        self.wm.automatic_upload = False
        src = self._make_log("fs", "fs_x.csv", "row\n")
        self.wm.compress_log(src)
        self.assertEqual(self.upload.uploaded, [])

    def test_thresholds_are_enlarged(self):
        # Guard the intent that each rotated log accumulates many events.
        self.assertGreaterEqual(self.wm.vfs_max_events, 80000)
        self.assertGreaterEqual(self.wm.block_max_events, 80000)
        self.assertGreaterEqual(self.wm.cache_max_events, 100000)
        self.assertGreaterEqual(self.wm.pagefault_max_events, 80000)
        self.assertGreaterEqual(self.wm.io_uring_max_events, 80000)
        # Dynamic minimums must stay consistent (min <= max) after enlargement.
        for name, (lo, hi) in self.wm.dynamic_limits.items():
            self.assertGreaterEqual(lo, 80000, name)
            self.assertLessEqual(lo, hi, name)


if __name__ == "__main__":
    unittest.main()
