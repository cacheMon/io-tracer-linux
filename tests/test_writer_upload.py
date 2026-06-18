"""
Unit tests for WriteManager's per-file upload behavior.

Trace logs are uploaded individually (no tar bundling), each under its own
subdirectory (fs, ds, cache, process, ...), and the per-stream flush
thresholds are sized so each rotated log is large. These tests use a fake
upload manager so no network or kernel access is required.

Run via either:
    python3 -m unittest discover -s tests
    pytest tests/
"""

import os
import sys
import tempfile
import types
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# WriterManager imports ObjectStorageManager, which imports `requests` at module
# load time. These tests never touch the network, and minimal CI environments do
# not install `requests`, so fall back to a stub module when it is unavailable.
if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["requests"] = types.ModuleType("requests")

# Compression uses Zstandard. Round-trip assertions are skipped when the
# optional dependency isn't installed (CI installs it explicitly).
try:
    import zstandard
    HAS_ZSTD = True
except ModuleNotFoundError:
    HAS_ZSTD = False


def _zstd_read_text(path):
    """Decompress a .zst file to text for round-trip assertions."""
    import zstandard
    dctx = zstandard.ZstdDecompressor()
    with open(path, "rb") as f, dctx.stream_reader(f) as reader:
        return reader.read().decode()


from src.tracer.WriterManager import WriteManager


class FakeUploadManager:
    """Minimal stand-in that records what would be uploaded."""

    def __init__(self):
        self.uploaded = []

    def append_object(self, file_path):
        self.uploaded.append(file_path)


class SilentWriteManager(WriteManager):
    """WriteManager with its background threads neutered for tests.

    ``__init__`` still spins up the adaptive-sizing and periodic-flush threads,
    but overriding their targets with no-ops makes them exit immediately so
    they neither linger across test runs nor fire timers during assertions.
    """

    def _adaptive_sizing(self):
        return

    def _periodic_flush(self):
        return


class PerFileUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_log(self, subdir, name, text):
        path = os.path.join(self.output_dir, subdir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_compress_log_uploads_individual_zst(self):
        src = self._make_log("fs", "fs_x.csv", "a,b,c\n1,2,3\n")
        self.wm.compress_log(src)

        # Exactly one upload, the compressed file — no tar bundle.
        self.assertEqual(len(self.upload.uploaded), 1)
        uploaded = self.upload.uploaded[0]
        self.assertTrue(uploaded.endswith(".csv.zst"))
        self.assertFalse(uploaded.endswith(".tar"))
        self.assertTrue(os.path.exists(uploaded))
        # Source .csv is removed once compressed.
        self.assertFalse(os.path.exists(src))
        # Content round-trips through Zstandard.
        self.assertEqual(_zstd_read_text(uploaded), "a,b,c\n1,2,3\n")

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_upload_preserves_subdirectory(self):
        # The backend file_type is derived from the parent directory, so each
        # stream must stay under its own subdir (fs, ds, cache, ...).
        for subdir in ("fs", "ds", "cache", "process"):
            src = self._make_log(subdir, f"{subdir}_x.csv", "row\n")
            self.wm.compress_log(src)

        self.assertEqual(len(self.upload.uploaded), 4)
        parents = {os.path.basename(os.path.dirname(p)) for p in self.upload.uploaded}
        self.assertEqual(parents, {"fs", "ds", "cache", "process"})

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_no_upload_when_automatic_disabled(self):
        self.wm.automatic_upload = False
        src = self._make_log("fs", "fs_x.csv", "row\n")
        self.wm.compress_log(src)
        self.assertEqual(self.upload.uploaded, [])

    def test_thresholds_are_enlarged(self):
        # Guard the intent that each rotated log accumulates many events.
        self.assertGreaterEqual(self.wm.vfs_max_events, 80000)
        self.assertGreaterEqual(self.wm.block_max_events, 80000)
        self.assertGreaterEqual(self.wm.cache_max_events, 100000)
        self.assertGreaterEqual(self.wm.pagefault_max_events, 80000)
        # Dynamic minimums must stay consistent (min <= max) after enlargement.
        for name, (lo, hi) in self.wm.dynamic_limits.items():
            self.assertGreaterEqual(lo, 80000, name)
            self.assertLessEqual(lo, hi, name)


class ZstandardMissingFallbackTests(unittest.TestCase):
    """When the optional ``zstandard`` library is unavailable, the tracer must
    keep (and upload) trace files uncompressed rather than losing data. These
    tests force the missing-dependency path so they run regardless of whether
    ``zstandard`` happens to be installed.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )
        # Pretend zstandard is not installed everywhere it is consulted.
        import src.utility.utils as utils_mod
        import src.tracer.WriterManager as wm_mod
        self._patchers = [
            unittest.mock.patch.object(utils_mod, "zstandard_available", lambda: None),
            unittest.mock.patch.object(wm_mod, "zstandard_available", lambda: None),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()
        import shutil
        try:
            self.wm.close_handles()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_log(self, subdir, name, text):
        path = os.path.join(self.output_dir, subdir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_compress_log_uploads_uncompressed_when_zstd_missing(self):
        src = self._make_log("process", "process_x.csv", "a,b,c\n1,2,3\n")
        self.wm.compress_log(src)

        # The uncompressed .csv is uploaded and left on disk; no .zst created.
        self.assertEqual(self.upload.uploaded, [src])
        self.assertTrue(os.path.exists(src))
        self.assertFalse(os.path.exists(src + ".zst"))
        with open(src) as f:
            self.assertEqual(f.read(), "a,b,c\n1,2,3\n")

    def test_compress_dir_falls_back_to_plain_tar(self):
        self.wm.automatic_upload = False
        self._make_log("process", "process_x.csv", "row\n")
        self.wm.compress_dir(self.output_dir)

        # A plain .tar bundle is produced instead of .tar.zst.
        self.assertTrue(os.path.exists(self.output_dir.rstrip("/") + ".tar"))
        self.assertFalse(os.path.exists(self.output_dir.rstrip("/") + ".tar.zst"))


class StaleLogRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )

    def tearDown(self):
        import shutil
        try:
            self.wm.close_handles()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_current(self, file_attr, text):
        """Simulate the periodic writer having flushed rows to a stream's file."""
        path = getattr(self.wm, file_attr)
        with open(path, "w") as f:
            f.write(text)
        return path

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_size_triggers_rotation(self):
        self.wm.max_file_bytes = 50
        self.wm.max_file_age = 10**9  # disable age trigger
        path = self._write_current("output_vfs_file", "x" * 100)  # > 50 bytes

        self.wm._maybe_rotate_stale_logs()

        self.assertEqual(len(self.upload.uploaded), 1)
        uploaded = self.upload.uploaded[0]
        self.assertTrue(uploaded.endswith(".csv.zst"))
        self.assertEqual(os.path.basename(os.path.dirname(uploaded)), "fs")
        # Rotated to a fresh file; the old .csv is gone (compressed away).
        self.assertNotEqual(self.wm.output_vfs_file, path)
        self.assertFalse(os.path.exists(path))

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_age_triggers_rotation(self):
        self.wm.max_file_bytes = 10**12  # disable size trigger
        self._write_current("output_block_file", "row\n")

        now = self.wm._stream_opened["block"] + self.wm.max_file_age + 1
        self.wm._maybe_rotate_stale_logs(now=now)

        self.assertEqual(len(self.upload.uploaded), 1)
        self.assertEqual(
            os.path.basename(os.path.dirname(self.upload.uploaded[0])), "ds"
        )

    def test_fresh_small_log_is_not_rotated(self):
        self._write_current("output_vfs_file", "row\n")
        self.wm._maybe_rotate_stale_logs()  # young and tiny
        self.assertEqual(self.upload.uploaded, [])

    def test_missing_or_empty_file_is_skipped(self):
        self.wm.max_file_age = 0  # treat everything as old
        # No file written yet, and an empty one for another stream.
        open(self.wm.output_cache_file, "w").close()
        self.wm._maybe_rotate_stale_logs()
        self.assertEqual(self.upload.uploaded, [])

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_rotate_flushes_buffered_rows(self):
        self.wm.vfs_buffer.append("a,b,c")
        self.wm.vfs_buffer.append("d,e,f")

        self.wm._rotate_stream("vfs")

        self.assertEqual(len(self.upload.uploaded), 1)
        content = _zstd_read_text(self.upload.uploaded[0])
        self.assertIn("a,b,c", content)
        self.assertIn("d,e,f", content)
        self.assertEqual(len(self.wm.vfs_buffer), 0)

    def test_rotation_defaults(self):
        self.assertEqual(self.wm.max_file_age, 20 * 60)
        self.assertEqual(self.wm.max_file_bytes, 100 * 1024 * 1024)
        # Snapshots must be excluded from generic rotation.
        self.assertNotIn("process", self.wm._streams)
        self.assertNotIn("fs_snap", self.wm._streams)


class MultiPartSnapshotHeaderTests(unittest.TestCase):
    """Multi-part filesystem snapshots are concatenated back into one CSV, so
    only the first part may carry the schema header — a header on parts 2+ would
    land mid-table as a bogus data row."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=False,
        )

    def tearDown(self):
        import shutil
        try:
            self.wm.close_handles()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_only_first_part_has_header(self):
        import glob
        from src.tracer import schema

        header = schema.header_line("filesystem_snapshot")

        # Part 1
        self.wm.fs_snap_buffer.append("rowA,1")
        self.wm.flush_fssnap_only()
        # Part 2
        self.wm.fs_snap_buffer.append("rowB,2")
        self.wm.flush_fssnap_only()

        parts = sorted(
            glob.glob(os.path.join(self.output_dir, "filesystem_snapshot", "*.zst"))
        )
        self.assertEqual(len(parts), 2)

        first = _zstd_read_text(parts[0]).splitlines()
        second = _zstd_read_text(parts[1]).splitlines()

        self.assertEqual(first[0], header)
        self.assertIn("rowA,1", first)
        # Part 2 must NOT repeat the header; concatenation would corrupt the CSV.
        self.assertNotIn(header, second)
        self.assertEqual(second[0], "rowB,2")


class NetworkStreamCompressionTests(unittest.TestCase):
    """Network streams (nw_conn/nw_sockopt/nw_drop) must be compressed
    and uploaded exactly like every other trace stream — both at shutdown
    (force_flush) and on mid-trace rotation."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.output_dir = os.path.join(self.tmp, "trace")
        self.upload = FakeUploadManager()
        self.wm = SilentWriteManager(
            output_dir=self.output_dir,
            upload_manager=self.upload,
            automatic_upload=True,
        )

    def tearDown(self):
        import shutil
        try:
            self.wm.close_handles()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_all_network_streams_registered_for_rotation(self):
        # Every network stream must be in the generic rotation registry so a
        # slow stream is compressed+uploaded mid-trace, not just at shutdown.
        for key in ("nw_conn", "nw_sockopt", "nw_drop"):
            self.assertIn(key, self.wm._streams, key)

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_force_flush_compresses_network_streams(self):
        self.wm.append_conn_log("ts,CONNECT,1,1,proc,AF_INET")
        self.wm.append_sockopt_log("ts,SET,1,proc,3")
        self.wm.append_drop_log("ts,PACKET_DROP,1,proc,TCP")

        self.wm.force_flush()

        # Each stream produced exactly one compressed upload under its own subdir.
        self.assertEqual(len(self.upload.uploaded), 3)
        subdirs = {os.path.basename(os.path.dirname(p)) for p in self.upload.uploaded}
        for sub in ("nw_conn", "nw_sockopt", "nw_drop"):
            self.assertIn(sub, subdirs, sub)
        for p in self.upload.uploaded:
            self.assertTrue(p.endswith(".csv.zst"), p)
            self.assertTrue(os.path.exists(p))

    @unittest.skipUnless(HAS_ZSTD, "zstandard not installed")
    def test_network_threshold_rotation_compresses(self):
        # Dropping the threshold forces a mid-trace rotation, which must
        # compress+upload the rotated file just like the continuous streams.
        self.wm.nw_conn_max_events = 3
        for i in range(7):
            self.wm.append_conn_log(f"row{i}")

        # 7 events at a threshold of 3 → 2 full rotations (2 uploads), with 1
        # event left buffered (force_flush is not called here).
        self.assertEqual(len(self.upload.uploaded), 2)
        for p in self.upload.uploaded:
            self.assertTrue(p.endswith(".csv.zst"), p)
            self.assertEqual(os.path.basename(os.path.dirname(p)), "nw_conn")


if __name__ == "__main__":
    unittest.main()
