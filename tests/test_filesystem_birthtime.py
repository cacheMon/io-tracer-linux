"""Tests for real file birth time via statx() in FilesystemSnapper.

statx STATX_BTIME returns the true inode birth time on filesystems that record
it; the helper must fall back to the supplied mtime when btime is unavailable
(old glibc, unsupported fs, or a missing path).
"""
import os
import time
import tempfile

from src.tracer.snappers import FilesystemSnapper
from src.tracer.snappers.FilesystemSnapper import get_birth_time


def test_birthtime_of_fresh_file_is_recent_or_fallback():
    """A just-created file's btime should be ~now; if the fs/libc has no btime
    the helper must return exactly the fallback (mtime), never garbage."""
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
        assert bt > 0
        assert abs(bt - st.st_mtime) < 5.0
        assert abs(bt - time.time()) < 60.0
    finally:
        os.unlink(path)


def test_birthtime_missing_path_returns_fallback():
    """statx on a nonexistent path fails (rc != 0) -> fallback returned."""
    sentinel = 123456.0
    assert get_birth_time("/nonexistent/path/should/not/exist/xyz", sentinel) == sentinel


def test_birthtime_disabled_short_circuits(monkeypatch):
    """When statx support has been disabled, the helper returns the fallback
    without touching libc."""
    monkeypatch.setattr(FilesystemSnapper, "_statx_supported", False)
    sentinel = 42.0
    assert get_birth_time("/etc/hostname", sentinel) == sentinel
