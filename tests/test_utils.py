"""
Unit tests for src.utility.utils.

These cover the pure-Python helpers that do not depend on bcc/kernel access,
so they run in any environment with a stdlib Python (no root, no eBPF).
Written with stdlib unittest so they run via either:
    python3 -m unittest discover -s tests
    pytest tests/
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utility.utils import (
    format_csv_row,
    simple_hash,
    hash_component,
    hash_filename_in_path,
    anonymize_path,
    inet4_from_event,
    evaluate_resource_tracing,
    auto_select_tracing,
    AUTO_TRACE_MIN_LOGICAL_CORES,
    AUTO_TRACE_MIN_TOTAL_RAM_GB,
    AUTO_TRACE_MIN_AVAIL_RAM_GB,
    AUTO_TRACE_MIN_NET_SPEED_MBPS,
)


class FormatCsvRowTests(unittest.TestCase):
    def test_plain_fields(self):
        self.assertEqual(format_csv_row("a", "b", "c"), "a,b,c")

    def test_no_trailing_newline(self):
        self.assertFalse(format_csv_row("a", "b").endswith("\n"))

    def test_quotes_fields_with_commas(self):
        self.assertEqual(format_csv_row("a", "b,c"), 'a,"b,c"')

    def test_escapes_embedded_quotes(self):
        self.assertEqual(format_csv_row('say "hi"'), '"say ""hi"""')

    def test_integers_are_stringified(self):
        self.assertEqual(format_csv_row(1, 2, 3), "1,2,3")


class HashTests(unittest.TestCase):
    def test_simple_hash_is_deterministic(self):
        self.assertEqual(simple_hash("hello"), simple_hash("hello"))

    def test_simple_hash_length_respected(self):
        self.assertEqual(len(simple_hash("hello", 8)), 8)

    def test_simple_hash_differs_for_different_input(self):
        self.assertNotEqual(simple_hash("a"), simple_hash("b"))

    def test_hash_component_preserves_extension(self):
        out = hash_component("document.txt")
        self.assertTrue(out.endswith(".txt"))
        self.assertNotIn("document", out)

    def test_hash_component_no_extension_when_disabled(self):
        out = hash_component("document.txt", keep_ext=False)
        self.assertFalse(out.endswith(".txt"))

    def test_hash_filename_in_path_keeps_directory_and_ext(self):
        out = hash_filename_in_path(Path("/home/user/secret.log"))
        self.assertTrue(out.startswith("/home/user/"))
        self.assertTrue(out.endswith(".log"))
        self.assertNotIn("secret", out)

    def test_anonymize_path_hashes_every_component(self):
        out = anonymize_path("/home/alice/clientX/.ssh/id_rsa")
        self.assertTrue(out.startswith("/"))
        # No cleartext component survives — not even the first directory.
        for leaked in ("home", "alice", "clientX", "id_rsa"):
            self.assertNotIn(leaked, out)
        # Directory depth (number of separators) is preserved.
        self.assertEqual(out.count("/"), "/home/alice/clientX/.ssh/id_rsa".count("/"))

    def test_anonymize_path_hashes_bare_basename(self):
        # The bug this guards against: hash_rel_path left short paths in cleartext.
        out = anonymize_path("id_rsa")
        self.assertNotIn("id_rsa", out)
        out2 = anonymize_path("proj/key.pem")
        self.assertNotIn("proj", out2)
        self.assertNotIn("key", out2)
        self.assertTrue(out2.endswith(".pem"))

    def test_anonymize_path_is_deterministic(self):
        p = "/var/log/secret.log"
        self.assertEqual(anonymize_path(p), anonymize_path(p))


class InetTests(unittest.TestCase):
    def test_inet4_roundtrip(self):
        # 127.0.0.1 in network byte order as a uint32
        import socket
        import struct
        packed = struct.unpack("!I", socket.inet_aton("127.0.0.1"))[0]
        self.assertEqual(inet4_from_event(packed), "127.0.0.1")


class ResourceTracingTests(unittest.TestCase):
    # A machine that comfortably clears every threshold.
    BIG = dict(
        logical_cores=AUTO_TRACE_MIN_LOGICAL_CORES,
        total_ram_gb=AUTO_TRACE_MIN_TOTAL_RAM_GB,
        available_ram_gb=AUTO_TRACE_MIN_AVAIL_RAM_GB,
        max_net_speed_mbps=AUTO_TRACE_MIN_NET_SPEED_MBPS,
    )

    def test_enough_of_everything_enables_both(self):
        d = evaluate_resource_tracing(**self.BIG)
        self.assertTrue(d["enable_cache"])
        self.assertTrue(d["enable_network"])

    def test_slow_network_keeps_cache_but_drops_network(self):
        d = evaluate_resource_tracing(**{**self.BIG, "max_net_speed_mbps": 1})
        self.assertTrue(d["enable_cache"])
        self.assertFalse(d["enable_network"])

    def test_too_few_cores_disables_both(self):
        d = evaluate_resource_tracing(**{**self.BIG, "logical_cores": 1})
        self.assertFalse(d["enable_cache"])
        self.assertFalse(d["enable_network"])

    def test_low_total_ram_disables_both(self):
        d = evaluate_resource_tracing(**{**self.BIG, "total_ram_gb": 2.0})
        self.assertFalse(d["enable_cache"])
        self.assertFalse(d["enable_network"])

    def test_low_available_ram_disables_both(self):
        d = evaluate_resource_tracing(**{**self.BIG, "available_ram_gb": 0.5})
        self.assertFalse(d["enable_cache"])
        self.assertFalse(d["enable_network"])

    def test_zero_resources_is_safe(self):
        d = evaluate_resource_tracing(0, 0, 0, 0)
        self.assertFalse(d["enable_cache"])
        self.assertFalse(d["enable_network"])

    def test_auto_select_never_disables_explicit_optin(self):
        # Even on a resource-starved host (detection returns zeros here since
        # psutil may be unavailable), an explicit request is preserved.
        cache, network = auto_select_tracing(True, True)
        self.assertTrue(cache)
        self.assertTrue(network)


if __name__ == "__main__":
    unittest.main()
