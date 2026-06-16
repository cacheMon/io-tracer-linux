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

    def test_epoll(self):
        self.assertEqual(FlagMapper.format_epoll_event_type(2), "EPOLL_WAIT")
        self.assertEqual(FlagMapper.format_epoll_op(1), "EPOLL_CTL_ADD")
        # EPOLLIN (0x1) | EPOLLOUT (0x4)
        decoded = FlagMapper.format_epoll_events(0x5)
        self.assertIn("EPOLLIN", decoded)
        self.assertIn("EPOLLOUT", decoded)

    def test_drop_and_tcp_state(self):
        self.assertEqual(FlagMapper.format_drop_event(0), "PACKET_DROP")
        self.assertEqual(FlagMapper.format_drop_event(1), "TCP_RETRANSMIT")
        self.assertEqual(FlagMapper.format_tcp_state(1), "ESTABLISHED")


if __name__ == "__main__":
    unittest.main()
