"""
Regression tests for IOTracer._cleanup shutdown correctness.

Two bugs are guarded here:
  1. _cleanup was not idempotent — a second signal (double Ctrl-C, SIGINT then
     SIGTERM) or the timed path's direct call ran detach_kprobes + flush + close
     twice on already-closed handles.
  2. _cleanup detached probes and closed the writer handles while the perf-buffer
     poll thread was still running, so a callback could write to a handle being
     torn down. The poll thread must be stopped and joined BEFORE close_handles.

These import IOTracer (which pulls in bcc); the module is skipped where bcc is
unavailable so it never breaks a minimal CI collection.
"""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# WriterManager -> ObjectStorageManager imports `requests`; stub it if absent.
if "requests" not in sys.modules:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["requests"] = types.ModuleType("requests")

# IOTracer does `from bcc import BPF`. The real bcc/BPF only loads under the
# system (root) python; these tests exercise the pure-Python _cleanup logic via
# object.__new__ and never touch BPF, so stub a BPF symbol when it's missing so
# the module imports anywhere (venv / minimal CI) without root or eBPF.
try:
    from bcc import BPF  # noqa: F401
except Exception:
    _bcc = sys.modules.get("bcc") or types.ModuleType("bcc")
    if not hasattr(_bcc, "BPF"):
        _bcc.BPF = type("BPF", (), {})
    sys.modules["bcc"] = _bcc

try:
    from src.tracer.IOTracer import IOTracer
    import src.tracer.IOTracer as iotracer_mod
    HAS_BCC = True
except Exception:
    HAS_BCC = False


class _Recorder:
    """Collects an ordered log of lifecycle calls across the fakes."""

    def __init__(self):
        self.calls = []


class _FakePoll:
    def __init__(self, rec):
        self.rec = rec
        self.polling_active = True


class _FakePollThread:
    def __init__(self, rec, poll):
        self.rec = rec
        self.poll = poll

    def join(self, timeout=None):
        # Record that the poll loop was asked to stop before we joined it.
        self.rec.calls.append(("poll_active", self.poll.polling_active))
        self.rec.calls.append("join")


class _FakeProbe:
    def __init__(self, rec):
        self.rec = rec

    def detach_kprobes(self):
        self.rec.calls.append("detach")


class _FakeSnapper:
    def __init__(self, rec, name):
        self.rec = rec
        self.name = name

    def stop_snapper(self):
        self.rec.calls.append(f"stop_{self.name}")


class _FakeWriter:
    def __init__(self, rec):
        self.rec = rec

    def write_to_disk(self):
        self.rec.calls.append("write_to_disk")

    def close_handles(self):
        self.rec.calls.append("close_handles")


@unittest.skipUnless(HAS_BCC, "bcc not importable in this environment")
class CleanupShutdownTests(unittest.TestCase):
    def _make_tracer(self):
        import threading
        t = object.__new__(IOTracer)  # bypass __init__ (no BPF/root needed)
        rec = _Recorder()
        t._cleanup_lock = threading.Lock()
        t._cleanup_done = False
        t.running = True
        t.verbose = False
        poll = _FakePoll(rec)
        t.polling_thread = poll
        t._poll_thread = _FakePollThread(rec, poll)
        t.probe_tracker = _FakeProbe(rec)
        t.fs_snapper = _FakeSnapper(rec, "fs")
        t.process_snapper = _FakeSnapper(rec, "proc")
        t.writer = _FakeWriter(rec)
        return t, rec

    def setUp(self):
        # Run the flush callback inline (no spinner thread / animation in tests).
        self._orig_spinner = iotracer_mod.run_with_spinner
        iotracer_mod.run_with_spinner = lambda label, fn, *a, **k: fn()

    def tearDown(self):
        iotracer_mod.run_with_spinner = self._orig_spinner

    def test_cleanup_runs_exactly_once(self):
        t, rec = self._make_tracer()
        t._cleanup(None, None)
        first = list(rec.calls)
        # Second + third entries (double signal / timed path) must be no-ops.
        t._cleanup(None, None)
        t._cleanup(None, None)
        self.assertEqual(rec.calls, first)
        self.assertEqual(rec.calls.count("detach"), 1)
        self.assertEqual(rec.calls.count("write_to_disk"), 1)
        self.assertEqual(rec.calls.count("close_handles"), 1)
        self.assertTrue(t._cleanup_done)
        self.assertFalse(t.running)

    def test_poll_thread_stopped_and_joined_before_handles_close(self):
        t, rec = self._make_tracer()
        t._cleanup(None, None)
        # The poll loop flag was cleared before the join...
        self.assertIn(("poll_active", False), rec.calls)
        # ...and the join happened before close_handles (no callback can run
        # against a handle being torn down).
        self.assertLess(rec.calls.index("join"), rec.calls.index("close_handles"))
        # detach precedes the buffer flush + close, too.
        self.assertLess(rec.calls.index("detach"), rec.calls.index("write_to_disk"))
        self.assertLess(rec.calls.index("write_to_disk"), rec.calls.index("close_handles"))

    def test_cleanup_safe_when_signal_arrives_during_startup(self):
        # Regression: the SIGINT/SIGTERM handler (_cleanup) is installed partway
        # through trace() startup, before self.polling_thread is assigned. A
        # signal in that window must NOT raise AttributeError — which would abort
        # cleanup with _cleanup_done already True, leaving probes attached and
        # buffers unflushed. _cleanup must tolerate polling_thread / _poll_thread
        # being absent (or None) and still detach + flush.
        t, rec = self._make_tracer()
        del t.polling_thread          # simulate the pre-assignment startup state
        del t._poll_thread
        t._cleanup(2, None)           # must not raise
        self.assertIn("detach", rec.calls)
        self.assertIn("write_to_disk", rec.calls)
        self.assertIn("close_handles", rec.calls)
        self.assertTrue(t._cleanup_done)


if __name__ == "__main__":
    unittest.main()
