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


if __name__ == "__main__":
    unittest.main()
