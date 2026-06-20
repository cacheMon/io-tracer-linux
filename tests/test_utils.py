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
import unittest.mock
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

    # The function is a hand-rolled hot path; these guard exact parity with the
    # stdlib csv default dialect (QUOTE_MINIMAL) it replaced.
    def test_none_is_empty_field(self):
        # csv renders None as an empty field (not the string "None").
        self.assertEqual(format_csv_row("a", None, "b"), "a,,b")

    def test_lone_empty_field_is_quoted(self):
        # A single empty field is written as "" so it stays distinguishable from
        # a zero-field (empty) row; multiple empty fields are not quoted.
        self.assertEqual(format_csv_row(""), '""')
        self.assertEqual(format_csv_row(None), '""')
        self.assertEqual(format_csv_row("", ""), ",")
        self.assertEqual(format_csv_row(), "")

    def test_quotes_fields_with_newline_or_cr(self):
        self.assertEqual(format_csv_row("a\nb"), '"a\nb"')
        self.assertEqual(format_csv_row("a\rb"), '"a\rb"')

    def test_matches_stdlib_csv_fuzz(self):
        import io as _io
        import csv as _csv
        import random as _random
        import string as _string

        def _ref(*fields):
            out = _io.StringIO()
            _csv.writer(out, lineterminator="").writerow(fields)
            return out.getvalue()

        _random.seed(1234)
        alpha = _string.printable + 'é—\t,"\n\r'
        for _ in range(20000):
            fields = []
            for _ in range(_random.randint(0, 6)):
                r = _random.random()
                if r < 0.2:
                    fields.append(_random.randint(-10**9, 10**9))
                elif r < 0.27:
                    fields.append(None)
                elif r < 0.34:
                    fields.append("")
                else:
                    fields.append("".join(_random.choice(alpha)
                                          for _ in range(_random.randint(0, 10))))
            self.assertEqual(format_csv_row(*fields), _ref(*fields), msg=repr(fields))


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

    def test_auto_select_does_not_auto_enable_cache(self):
        # Page-cache tracing is the highest-volume stream (~1 CPU core on a busy
        # host), so it must NEVER be auto-enabled from spare resources — only an
        # explicit --cache turns it on. Network stays auto-enabled on a capable,
        # fast-linked host.
        big = dict(
            logical_cores=64,
            total_ram_gb=512.0,
            available_ram_gb=256.0,
            max_net_speed_mbps=10000,
        )
        with unittest.mock.patch(
            "src.utility.utils.detect_host_resources", return_value=big
        ):
            cache, network = auto_select_tracing(False, False)
            self.assertFalse(cache)   # not auto-enabled despite a huge host
            self.assertTrue(network)  # network still auto-enabled

            cache_optin, _ = auto_select_tracing(True, False)
            self.assertTrue(cache_optin)  # explicit --cache honored


if __name__ == "__main__":
    unittest.main()
