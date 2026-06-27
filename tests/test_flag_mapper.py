"""
Unit tests for src.tracer.FlagMapper.

FlagMapper has no external dependencies, so its decoding logic is fully
unit-testable without a kernel or bcc.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer.FlagMapper import FlagMapper


class FsFlagTests(unittest.TestCase):
    def setUp(self):
        self.m = FlagMapper()

    def test_rdonly(self):
        self.assertEqual(self.m.format_fs_flags(0o0), "O_RDONLY")

    def test_rdwr_creat(self):
        # O_RDWR (0o2) | O_CREAT (0o100)
        self.assertEqual(self.m.format_fs_flags(0o102), "O_RDWR|O_CREAT")

    def test_wronly_append(self):
        # O_WRONLY (0o1) | O_APPEND (0o2000)
        out = self.m.format_fs_flags(0o2001)
        self.assertIn("O_WRONLY", out)
        self.assertIn("O_APPEND", out)

    def test_sync_supersedes_dsync(self):
        # O_SYNC's mask includes the O_DSYNC bit; only O_SYNC should appear.
        out = self.m.format_fs_flags(0o4010002)  # O_RDWR | O_SYNC
        self.assertIn("O_SYNC", out)
        self.assertNotIn("O_DSYNC", out)

    def test_tmpfile_supersedes_directory(self):
        # O_TMPFILE's mask includes the O_DIRECTORY bit; only O_TMPFILE appears.
        out = self.m.format_fs_flags(0o20200002)  # O_RDWR | O_TMPFILE
        self.assertIn("O_TMPFILE", out)
        self.assertNotIn("O_DIRECTORY", out)

    def test_invalid_access_mode_no_flags(self):
        # access bits 0b11 is invalid and matches no other flag -> NO_FLAGS.
        self.assertEqual(self.m.format_fs_flags(0o3), "NO_FLAGS")

    def test_fast_path_matches_general_path(self):
        # The flags==0 fast path must equal the full scan's output, and the
        # optimized scan must reproduce the original loop's output exactly
        # (byte-for-byte, including flag ordering) across a wide input range.
        # A reference copy of the pre-optimization implementation guards
        # against any output regression from the precomputed-plan rewrite.
        flag_map = self.m.flag_fs_map

        def reference(flags):
            access_mode = flags & 0o3
            access_str = None
            if access_mode == 0o0:
                access_str = "O_RDONLY"
            elif access_mode == 0o1:
                access_str = "O_WRONLY"
            elif access_mode == 0o2:
                access_str = "O_RDWR"
            result = []
            if access_str:
                result.append(access_str)
            for flag, name in flag_map.items():
                if name in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
                    continue
                if name == "O_SYNC" and (flags & 0o04010000) == 0o04010000:
                    result.append(name)
                    if "O_DSYNC" in result:
                        result.remove("O_DSYNC")
                    continue
                if name == "O_TMPFILE" and (flags & 0o020200000) == 0o020200000:
                    result.append(name)
                    if "O_DIRECTORY" in result:
                        result.remove("O_DIRECTORY")
                    continue
                if name not in ["O_SYNC", "O_TMPFILE"] and flags & flag:
                    result.append(name)
            return "|".join(result) if result else "NO_FLAGS"

        # Dense low range + every known bit + all pairs/triples of known bits.
        known = list(flag_map.keys())
        candidates = set(range(0, 4096))
        candidates.update(known)
        for a in known:
            for b in known:
                candidates.add(a | b)
                for c in known:
                    candidates.add(a | b | c)
        for flags in candidates:
            self.assertEqual(self.m.format_fs_flags(flags), reference(flags),
                             msg=f"flags={oct(flags)}")


class MmapProtTests(unittest.TestCase):
    def setUp(self):
        self.m = FlagMapper()

    def test_prot_none(self):
        self.assertEqual(self.m.format_mmap_prot_flags(0), "PROT_NONE")

    def test_no_map(self):
        self.assertEqual(self.m.format_mmap_map_flags(0), "NO_MAP")


class ErrnoTests(unittest.TestCase):
    def test_zero_is_empty(self):
        self.assertEqual(FlagMapper.format_errno(0), "")

    def test_known_errno(self):
        self.assertEqual(FlagMapper.format_errno(2), "ENOENT")

    def test_magnitude_is_taken(self):
        # Callers pass -ret; format_errno should accept either sign.
        self.assertEqual(FlagMapper.format_errno(-13), "EACCES")

    def test_unknown_errno_falls_back(self):
        self.assertEqual(FlagMapper.format_errno(99999), "ERRNO(99999)")


class FsTypeTests(unittest.TestCase):
    def test_zero_is_empty(self):
        self.assertEqual(FlagMapper.format_fs_type(0), "")

    def test_ext_magic(self):
        self.assertEqual(FlagMapper.format_fs_type(0xEF53), "EXT2/3/4")

    def test_unknown_magic_falls_back(self):
        self.assertEqual(FlagMapper.format_fs_type(0x1234), "FS(0x1234)")


class OpTypeTests(unittest.TestCase):
    def test_op_fs_types_known(self):
        m = FlagMapper()
        self.assertEqual(m.op_fs_types.get(3), "OPEN")
        self.assertEqual(m.op_fs_types.get(1), "READ")


class NetworkFlagTests(unittest.TestCase):
    """Decoding helpers for the opt-in low-overhead network subset."""

    def test_conn_event(self):
        self.assertEqual(FlagMapper.format_conn_event(0), "SOCKET_CREATE")
        self.assertEqual(FlagMapper.format_conn_event(4), "CONNECT")
        self.assertEqual(FlagMapper.format_conn_event(99), "CONN(99)")

    def test_proto_and_domain(self):
        self.assertEqual(FlagMapper.format_proto(6), "TCP")
        self.assertEqual(FlagMapper.format_proto(17), "UDP")
        self.assertEqual(FlagMapper.format_proto(255), "PROTO(255)")
        self.assertEqual(FlagMapper.format_domain(2), "AF_INET")
        self.assertEqual(FlagMapper.format_domain(10), "AF_INET6")

    def test_sock_type_and_shutdown(self):
        self.assertEqual(FlagMapper.format_sock_type(1), "SOCK_STREAM")
        self.assertEqual(FlagMapper.format_shutdown_how(2), "SHUT_RDWR")

    def test_sockopt(self):
        self.assertEqual(FlagMapper.format_sockopt(1, 2), "SO_REUSEADDR")
        self.assertEqual(FlagMapper.format_sockopt(6, 1), "TCP_NODELAY")
        self.assertEqual(FlagMapper.format_sockopt(6, 999), "OPT(6,999)")
        self.assertEqual(FlagMapper.format_sockopt_event(0), "SET")

    def test_drop_and_tcp_state(self):
        self.assertEqual(FlagMapper.format_drop_event(0), "PACKET_DROP")
        self.assertEqual(FlagMapper.format_drop_event(1), "TCP_RETRANSMIT")
        self.assertEqual(FlagMapper.format_tcp_state(1), "ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
