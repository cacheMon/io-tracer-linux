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
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
