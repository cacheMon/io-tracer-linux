"""
Unit tests for FilesystemSnapper delta behavior.

The first snapshot records a full filesystem inventory; every subsequent
snapshot records only added / modified / deleted files (a delta), so the
tracer no longer re-uploads the entire inventory every hour. These tests drive
``filesystem_snapshot()`` directly against a temporary directory tree using a
fake WriteManager that captures the rows that would be written.
"""

import csv
import io
import os
import sys
import tempfile
import types
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importing FilesystemSnapper pulls in WriterManager -> ObjectStorageManager,
# which imports `requests` at module load time. These tests never touch the
# network, and minimal CI environments do not install `requests`, so fall back
# to a stub module when it is unavailable (mirrors test_writer_upload.py).
if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["requests"] = types.ModuleType("requests")

from src.tracer.snappers.FilesystemSnapper import FilesystemSnapper, DELETED_SIZE


class FakeWriteManager:
    """Captures snapshot rows and flush/complete calls per snapshot pass."""

    def __init__(self):
        self.rows = []
        self.flushes = 0
        self.completes = 0

    def append_fs_snap_log(self, out):
        self.rows.append(out)

    def flush_fssnap_only(self):
        self.flushes += 1

    def mark_fs_snapshot_complete(self):
        self.completes += 1

    # Test helpers -----------------------------------------------------------
    def take(self):
        """Return rows captured since the last take() and reset the buffer."""
        rows = self.rows
        self.rows = []
        return rows


def _paths_and_sizes(rows):
    """Parse {path: size} out of captured CSV rows."""
    out = {}
    for row in rows:
        fields = next(csv.reader(io.StringIO(row)))
        out[fields[1]] = int(fields[2])
    return out


class FilesystemSnapperDeltaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.wm = FakeWriteManager()
        self.snapper = FilesystemSnapper(self.wm, anonymous=False)
        self.snapper.root_path = self.tmp

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def _bump_mtime(self, path, content):
        """Rewrite a file and force a clearly newer mtime."""
        with open(path, "w") as f:
            f.write(content)
        st = os.stat(path)
        os.utime(path, (st.st_atime, st.st_mtime + 100))

    def test_first_snapshot_is_full(self):
        self._write("a.txt", "a")
        self._write("sub/b.txt", "bb")

        self.assertTrue(self.snapper.filesystem_snapshot())
        rows = _paths_and_sizes(self.wm.take())

        self.assertEqual(
            set(rows),
            {os.path.join(self.tmp, "a.txt"), os.path.join(self.tmp, "sub/b.txt")},
        )
        self.assertEqual(self.wm.flushes, 1)
        self.assertEqual(self.wm.completes, 1)

    def test_unchanged_delta_is_empty(self):
        self._write("a.txt", "a")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        # Second pass with no changes emits nothing.
        self.snapper._visited_inodes.clear()
        self.assertTrue(self.snapper.filesystem_snapshot())
        self.assertEqual(self.wm.take(), [])

    def test_delta_reports_added_and_modified(self):
        a = self._write("a.txt", "a")
        self._write("b.txt", "b")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        # Modify a.txt and add c.txt; b.txt is untouched.
        self._bump_mtime(a, "aaaa")
        self._write("c.txt", "c")

        self.snapper._visited_inodes.clear()
        self.snapper.filesystem_snapshot()
        rows = _paths_and_sizes(self.wm.take())

        self.assertEqual(
            set(rows),
            {os.path.join(self.tmp, "a.txt"), os.path.join(self.tmp, "c.txt")},
        )
        # Sizes reflect current state, not a tombstone.
        self.assertEqual(rows[os.path.join(self.tmp, "a.txt")], 4)
        self.assertEqual(rows[os.path.join(self.tmp, "c.txt")], 1)

    def test_delta_reports_deletion_as_tombstone(self):
        self._write("a.txt", "a")
        b = self._write("b.txt", "b")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        os.remove(b)
        self.snapper._visited_inodes.clear()
        self.snapper.filesystem_snapshot()
        rows = _paths_and_sizes(self.wm.take())

        self.assertEqual(set(rows), {os.path.join(self.tmp, "b.txt")})
        self.assertEqual(rows[os.path.join(self.tmp, "b.txt")], DELETED_SIZE)

    def test_interrupted_snapshot_does_not_advance_baseline(self):
        self._write("a.txt", "a")
        # Interrupt before the first snapshot can complete.
        self.snapper.interrupt = True
        self.assertFalse(self.snapper.filesystem_snapshot())
        self.assertFalse(self.snapper._have_full_snapshot)
        self.assertEqual(self.wm.flushes, 0)
        self.assertEqual(self.wm.completes, 0)

        # Recover: the next completed pass is still a full snapshot.
        self.snapper.interrupt = False
        self.snapper._visited_inodes.clear()
        self.assertTrue(self.snapper.filesystem_snapshot())
        rows = _paths_and_sizes(self.wm.take())
        self.assertEqual(set(rows), {os.path.join(self.tmp, "a.txt")})

    def test_delta_reports_subtree_removal_as_tombstones(self):
        self._write("keep.txt", "k")
        self._write("sub/b.txt", "b")
        self._write("sub/c.txt", "c")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        # Remove an entire subdirectory: its files must still be tombstoned even
        # though scan_dir is never invoked on the now-missing directory.
        import shutil
        shutil.rmtree(os.path.join(self.tmp, "sub"))

        self.snapper._visited_inodes.clear()
        self.snapper.filesystem_snapshot()
        rows = _paths_and_sizes(self.wm.take())

        self.assertEqual(
            set(rows),
            {os.path.join(self.tmp, "sub/b.txt"), os.path.join(self.tmp, "sub/c.txt")},
        )
        self.assertTrue(all(v == DELETED_SIZE for v in rows.values()))

    def test_transient_scandir_error_does_not_tombstone(self):
        # A directory that can't be listed this pass (e.g. PermissionError) must
        # not have its contents reported as deleted.
        self._write("keep.txt", "k")
        self._write("sub/b.txt", "b")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        target = os.path.join(self.tmp, "sub")
        real_scandir = os.scandir

        def fake_scandir(path):
            if os.path.abspath(path) == target:
                raise PermissionError(13, "Permission denied")
            return real_scandir(path)

        self.snapper._visited_inodes.clear()
        with unittest.mock.patch(
            "src.tracer.snappers.FilesystemSnapper.os.scandir", side_effect=fake_scandir
        ):
            self.snapper.filesystem_snapshot()

        # No tombstones; sub/b.txt is carried forward into the new baseline.
        self.assertEqual(self.wm.take(), [])
        self.assertIn(os.path.join(self.tmp, "sub/b.txt"), self.snapper._prev_state)

    def test_transient_file_stat_error_carries_over(self):
        # A single file we fail to stat (transient) is carried over, not deleted;
        # the same failure as a genuine absence (FileNotFoundError) tombstones.
        a_path = self._write("a.txt", "a")
        self.snapper.filesystem_snapshot()
        self.wm.take()

        class _RaisingEntry:
            def __init__(self, path, exc):
                self.path = path
                self._exc = exc

            def is_file(self, follow_symlinks=True):
                return True

            def is_symlink(self):
                return False

            def is_dir(self, follow_symlinks=True):
                return False

            def stat(self, follow_symlinks=True):
                raise self._exc

        class _FakeScandirCtx:
            def __init__(self, entries):
                self._entries = entries

            def __enter__(self):
                return iter(self._entries)

            def __exit__(self, *exc):
                return False

        real_scandir = os.scandir

        def patched(exc):
            def fake_scandir(path):
                if os.path.abspath(path) == os.path.abspath(self.tmp):
                    return _FakeScandirCtx([_RaisingEntry(a_path, exc)])
                return real_scandir(path)
            return fake_scandir

        # Transient (PermissionError): carried over, no tombstone.
        self.snapper._visited_inodes.clear()
        with unittest.mock.patch(
            "src.tracer.snappers.FilesystemSnapper.os.scandir",
            side_effect=patched(PermissionError(13, "denied")),
        ):
            self.snapper.filesystem_snapshot()
        self.assertEqual(self.wm.take(), [])
        self.assertIn(a_path, self.snapper._prev_state)

        # Absence (FileNotFoundError): tombstoned.
        self.snapper._visited_inodes.clear()
        with unittest.mock.patch(
            "src.tracer.snappers.FilesystemSnapper.os.scandir",
            side_effect=patched(FileNotFoundError(2, "missing")),
        ):
            self.snapper.filesystem_snapshot()
        rows = _paths_and_sizes(self.wm.take())
        self.assertEqual(rows, {a_path: DELETED_SIZE})

    def test_pseudo_fs_subtree_is_skipped(self):
        # A directory whose filesystem is detected as pseudo (e.g. a /proc or
        # /sys mount) must not be descended into or inventoried, while sibling
        # real-storage files are still captured.
        self._write("real.txt", "r")
        self._write("proc/cmdline", "x")
        self._write("proc/deep/stat", "y")

        pseudo_dir = os.path.abspath(os.path.join(self.tmp, "proc"))
        real_stat = os.stat

        class _FakeStat:
            # Wrap a real stat_result but override st_dev so 'proc' looks like a
            # separate mount, which is what triggers the pseudo-fs boundary check.
            def __init__(self, st, dev):
                self._st = st
                self.st_dev = dev
                self.st_ino = st.st_ino

            def __getattr__(self, name):
                return getattr(self._st, name)

        def stat_with_fake_dev(path, *a, **k):
            st = real_stat(path, *a, **k)
            if os.path.abspath(path) == pseudo_dir:
                return _FakeStat(st, -12345)  # distinct device id => mount boundary
            return st

        def fake_is_pseudo_fs(path):
            return os.path.abspath(path) == pseudo_dir

        with unittest.mock.patch(
            "src.tracer.snappers.FilesystemSnapper.is_pseudo_fs",
            side_effect=fake_is_pseudo_fs,
        ), unittest.mock.patch(
            "src.tracer.snappers.FilesystemSnapper.os.stat",
            side_effect=stat_with_fake_dev,
        ):
            self.assertTrue(self.snapper.filesystem_snapshot())

        rows = _paths_and_sizes(self.wm.take())
        self.assertIn(os.path.join(self.tmp, "real.txt"), rows)
        self.assertNotIn(os.path.join(self.tmp, "proc/cmdline"), rows)
        self.assertNotIn(os.path.join(self.tmp, "proc/deep/stat"), rows)

    def test_anonymous_delta_emits_hashed_paths(self):
        self._write("secret.txt", "x")
        self.snapper.anonymous = True
        self.snapper.filesystem_snapshot()
        rows = self.wm.take()
        # Real path must not leak in anonymous mode.
        self.assertTrue(rows)
        for row in rows:
            self.assertNotIn("secret.txt", row)


if __name__ == "__main__":
    unittest.main()
