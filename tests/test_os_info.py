"""
Unit tests for the OS-information / failure-diagnostics dump.

When the eBPF prober cannot compile or the tracer fails to run, SystemSnapper
collects as much of the OS / kernel / toolchain environment as possible and
writes it to a local JSON file the user can share with the maintainers. These
tests exercise that collection directly — no bcc, no root, no real BPF.

Importing SystemSnapper transitively pulls in WriterManager ->
ObjectStorageManager (which imports ``requests``) and SystemSnapper itself
imports ``psutil``. Minimal CI environments install neither, so stub them
before import (mirrors the other tests' handling of ``requests``). The
diagnostics code only calls ``psutil`` inside individually-guarded sections, so
a bare stub is enough for the import to succeed.
"""

import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

for _mod in ("requests", "psutil"):
    if _mod not in sys.modules:
        try:
            __import__(_mod)
        except ModuleNotFoundError:
            sys.modules[_mod] = types.ModuleType(_mod)

from src.tracer.snappers.SystemSnapper import SystemSnapper


class _FakeWriteManager:
    """Minimal stand-in; the diagnostics path never touches the writer."""


def _make_snapper():
    return SystemSnapper(writer_manager=_FakeWriteManager())


class GetOsInfoTests(unittest.TestCase):
    def test_core_fields_present(self):
        info = _make_snapper().get_os_info(include_country=False)
        for key in ("system", "release", "version", "machine", "hostname"):
            self.assertIn(key, info)

    def test_country_skipped_when_disabled(self):
        # include_country=False must not perform the network geolocation call.
        info = _make_snapper().get_os_info(include_country=False)
        self.assertNotIn("country", info)


class CollectDiagnosticsTests(unittest.TestCase):
    def _collect_with_error(self):
        snapper = _make_snapper()
        try:
            raise RuntimeError("verifier rejected program")
        except RuntimeError as e:
            return snapper.collect_diagnostics(
                error=e,
                attempted_cflags=["-Wno-macro-redefined", "-DHAS_CMD_FLAGS"],
                bpf_file="/path/to/prober.c",
                context="unit test failure",
            )

    def test_top_level_structure(self):
        diag = self._collect_with_error()
        for key in ("io_tracer_diagnostics", "error", "attempt",
                    "bpf_environment", "system"):
            self.assertIn(key, diag)

    def test_error_captured_with_traceback(self):
        diag = self._collect_with_error()
        self.assertEqual(diag["error"]["type"], "RuntimeError")
        self.assertEqual(diag["error"]["message"], "verifier rejected program")
        self.assertIn("RuntimeError", diag["error"]["traceback"])
        self.assertIn("verifier rejected program", diag["error"]["traceback"])

    def test_attempt_records_inputs(self):
        diag = self._collect_with_error()
        self.assertEqual(diag["attempt"]["bpf_source"], "/path/to/prober.c")
        self.assertEqual(
            diag["attempt"]["cflags"],
            ["-Wno-macro-redefined", "-DHAS_CMD_FLAGS"],
        )

    def test_bpf_environment_sections(self):
        diag = self._collect_with_error()
        for key in ("kernel", "btf", "kernel_config", "toolchain",
                    "kernel_headers", "tracefs"):
            self.assertIn(key, diag["bpf_environment"])

    def test_system_sections_have_no_country(self):
        diag = self._collect_with_error()
        for key in ("os", "cpu", "memory"):
            self.assertIn(key, diag["system"])
        os_section = diag["system"]["os"]
        if isinstance(os_section, dict):
            self.assertNotIn("country", os_section)

    def test_result_is_json_serializable(self):
        diag = self._collect_with_error()
        # Must round-trip cleanly — it is written as JSON on the failure path.
        json.loads(json.dumps(diag))

    def test_works_without_error_argument(self):
        diag = _make_snapper().collect_diagnostics()
        self.assertNotIn("error", diag)
        self.assertIn("bpf_environment", diag)


class SanitizeCmdlineTests(unittest.TestCase):
    def test_redacts_secret_tokens_keeps_the_rest(self):
        cmdline = (
            "BOOT_IMAGE=/vmlinuz root=UUID=abc ro lockdown=integrity "
            "provisioning_token=SUPERSECRET ds_secret=hunter2 quiet"
        )
        out = SystemSnapper._sanitize_cmdline(cmdline)
        # Diagnostically useful params are preserved verbatim.
        self.assertIn("lockdown=integrity", out)
        self.assertIn("root=UUID=abc", out)
        self.assertIn("ro", out)
        self.assertIn("quiet", out)
        # Secret-looking values are redacted, key kept for context.
        self.assertIn("provisioning_token=<redacted>", out)
        self.assertIn("ds_secret=<redacted>", out)
        self.assertNotIn("SUPERSECRET", out)
        self.assertNotIn("hunter2", out)

    def test_handles_empty_and_none(self):
        self.assertIsNone(SystemSnapper._sanitize_cmdline(None))
        self.assertEqual(SystemSnapper._sanitize_cmdline(""), "")


class DumpFailureDiagnosticsTests(unittest.TestCase):
    def test_writes_valid_json_file(self):
        snapper = _make_snapper()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                raise OSError("Failed to load BPF program")
            except OSError as e:
                path = snapper.dump_failure_diagnostics(
                    error=e,
                    attempted_cflags=["-mllvm", "-bpf-stack-size=4096"],
                    bpf_file="/path/to/prober.c",
                    context="BPF program failed to compile or load",
                    dest_dir=tmp,
                )

            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(os.path.dirname(path), tmp)
            self.assertTrue(os.path.basename(path).startswith("io-tracer-os-info_"))

            with open(path) as f:
                loaded = json.load(f)
            self.assertEqual(loaded["error"]["message"], "Failed to load BPF program")
            self.assertEqual(loaded["attempt"]["bpf_source"], "/path/to/prober.c")

    def test_never_raises_and_returns_path(self):
        # Even with no inputs at all, the dump must succeed and produce a file.
        snapper = _make_snapper()
        with tempfile.TemporaryDirectory() as tmp:
            path = snapper.dump_failure_diagnostics(dest_dir=tmp)
            self.assertIsNotNone(path)
            self.assertTrue(os.path.isfile(path))


if __name__ == "__main__":
    unittest.main()
