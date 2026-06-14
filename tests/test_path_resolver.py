"""
Unit tests for src.tracer.PathResolver.

Focuses on the in-memory cache behaviour — especially cleanup_old_cache, which
is the bounded-memory safety valve for long-running traces — without touching
/proc.
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer.PathResolver import PathResolver


class ResolvePathTests(unittest.TestCase):
    def test_cache_hit_returns_path(self):
        r = PathResolver()
        r.inode_to_path[42] = "/tmp/foo"
        self.assertEqual(r.resolve_path(42), "/tmp/foo")

    def test_fallback_to_filename(self):
        r = PathResolver()
        self.assertEqual(r.resolve_path(7, filename="bar.txt"), "bar.txt")

    def test_fallback_to_inode_marker(self):
        r = PathResolver()
        self.assertEqual(r.resolve_path(7), "[inode:7]")


class CleanupOldCacheTests(unittest.TestCase):
    def test_prunes_stale_pids(self):
        r = PathResolver(cache_timeout=10)
        # last_update older than cache_timeout * 10 should be removed
        stale_pid = 1234
        r.pid_to_files[stale_pid] = {1: "/a"}
        r.last_update[stale_pid] = time.time() - (r.cache_timeout * 10 + 5)

        fresh_pid = 5678
        r.pid_to_files[fresh_pid] = {2: "/b"}
        r.last_update[fresh_pid] = time.time()

        r.cleanup_old_cache()

        self.assertNotIn(stale_pid, r.pid_to_files)
        self.assertNotIn(stale_pid, r.last_update)
        self.assertIn(fresh_pid, r.pid_to_files)

    def test_caps_inode_cache(self):
        r = PathResolver()
        for i in range(10001):
            r.inode_to_path[i] = f"/path/{i}"
        r.cleanup_old_cache()
        # Over the 10000 threshold it trims to the most recent 5000 entries.
        self.assertEqual(len(r.inode_to_path), 5000)
        # The most recently inserted entries are the ones retained.
        self.assertIn(10000, r.inode_to_path)

    def test_is_idempotent_when_small(self):
        r = PathResolver()
        r.inode_to_path[1] = "/a"
        r.cleanup_old_cache()
        self.assertEqual(r.inode_to_path, {1: "/a"})


class ResolveRelativeTests(unittest.TestCase):
    def test_absolute_path_returned_unchanged(self):
        r = PathResolver()
        # Absolute paths need no resolution and must not touch /proc.
        with mock.patch("src.tracer.PathResolver.os.readlink") as rl:
            self.assertEqual(
                r.resolve_relative(pid=1, dirfd=PathResolver.AT_FDCWD, relpath="/etc/passwd"),
                "/etc/passwd",
            )
            rl.assert_not_called()

    def test_missing_pid_or_relpath_returns_relpath(self):
        r = PathResolver()
        self.assertEqual(r.resolve_relative(pid=0, dirfd=-100, relpath="a.txt"), "a.txt")
        self.assertEqual(r.resolve_relative(pid=5, dirfd=-100, relpath=""), "")

    def test_cwd_relative_joined_and_normalised(self):
        r = PathResolver()
        with mock.patch("src.tracer.PathResolver.os.readlink", return_value="/home/user/proj"):
            out = r.resolve_relative(pid=99, dirfd=PathResolver.AT_FDCWD,
                                     relpath="../data/x.bin", inode=7)
        self.assertEqual(out, "/home/user/data/x.bin")
        # Successful resolution populates the inode cache.
        self.assertEqual(r.inode_to_path[7], "/home/user/data/x.bin")

    def test_dirfd_relative_uses_fd_link(self):
        r = PathResolver()
        with mock.patch("src.tracer.PathResolver.os.readlink", return_value="/var/log") as rl:
            out = r.resolve_relative(pid=99, dirfd=5, relpath="app/run.log")
        self.assertEqual(out, "/var/log/app/run.log")
        rl.assert_called_once_with("/proc/99/fd/5")

    def test_pseudo_dir_base_falls_back(self):
        r = PathResolver()
        with mock.patch("src.tracer.PathResolver.os.readlink", return_value="pipe:[12345]"):
            self.assertEqual(r.resolve_relative(pid=99, dirfd=5, relpath="x"), "x")

    def test_oserror_falls_back_to_relpath(self):
        r = PathResolver()
        with mock.patch("src.tracer.PathResolver.os.readlink", side_effect=OSError):
            self.assertEqual(
                r.resolve_relative(pid=99, dirfd=PathResolver.AT_FDCWD, relpath="x.txt"),
                "x.txt",
            )


if __name__ == "__main__":
    unittest.main()
