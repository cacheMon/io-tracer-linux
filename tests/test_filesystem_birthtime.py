"""Tests for real file birth time via statx() in FilesystemSnapper.

statx STATX_BTIME returns the true inode birth time on filesystems that record
it; the helper must fall back to the supplied mtime when btime is unavailable
(old glibc, unsupported fs, or a missing path).
"""
import os
import sys
import time
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importing FilesystemSnapper pulls in WriterManager -> ObjectStorageManager,
# which imports `requests` at module load time. These tests never touch the
# network, and minimal CI environments do not install `requests`, so fall back
# to a stub module when it is unavailable (mirrors test_fs_snapshot_delta.py).
if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["requests"] = types.ModuleType("requests")

from src.tracer.snappers import FilesystemSnapper
from src.tracer.snappers.FilesystemSnapper import get_birth_time


class BirthTimeTests(unittest.TestCase):
    def test_birthtime_of_fresh_file_is_recent_or_fallback(self):
        """A just-created file's btime should be ~now; if the fs/libc has no
        btime the helper must return exactly the fallback (mtime), never
        garbage."""
        with tempfile.NamedTemporaryFile(prefix="btime_", delete=False) as f:
            path = f.name
        try:
            st = os.stat(path)
            fallback = st.st_mtime
            bt = get_birth_time(path, fallback)
            if bt == fallback:
                # btime not recorded for this file/fs — acceptable fallback path.
                return
            # Real btime: must be a sane epoch close to the file's mtime/now.
            self.assertGreater(bt, 0)
            self.assertLess(abs(bt - st.st_mtime), 5.0)
            self.assertLess(abs(bt - time.time()), 60.0)
        finally:
            os.unlink(path)

    def test_birthtime_missing_path_returns_fallback(self):
        """statx on a nonexistent path fails (rc != 0) -> fallback returned."""
        sentinel = 123456.0
        self.assertEqual(
            get_birth_time("/nonexistent/path/should/not/exist/xyz", sentinel),
            sentinel,
        )

    def test_birthtime_disabled_short_circuits(self):
        """When statx support has been disabled, the helper returns the
        fallback without touching libc."""
        saved = FilesystemSnapper._statx_supported
        FilesystemSnapper._statx_supported = False
        try:
            sentinel = 42.0
            self.assertEqual(get_birth_time("/etc/hostname", sentinel), sentinel)
        finally:
            FilesystemSnapper._statx_supported = saved


if __name__ == "__main__":
    unittest.main()
