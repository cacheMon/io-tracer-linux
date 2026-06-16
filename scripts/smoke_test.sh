#!/usr/bin/env bash
#
# smoke_test.sh — verify the eBPF program compiles, loads, and produces output.
#
# The tracer's BPF C cannot be statically verified; the only real check is to
# load it on the target kernel/arch. This runs iotrc briefly (no upload) in a
# few configurations, generates some I/O, then confirms:
#   * the BPF program compiled and attached (no verifier/attach errors), and
#   * trace shards were written with the expected CSV header.
#
# Run on BOTH x86_64 and aarch64, since several probes/tracepoints are
# arch-specific (legacy select/poll/epoll_wait vs pselect6/ppoll/epoll_pwait,
# openat/mremap syscall wrappers, etc.).
#
# Usage:  sudo bash scripts/smoke_test.sh [run_seconds]
#
set -u

RUN_SECONDS="${1:-20}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
ARCH="$(uname -m)"
KREL="$(uname -r)"
FAIL=0

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: must run as root (sudo)." >&2
  exit 1
fi

echo "=== io-tracer smoke test ==="
echo "arch=$ARCH kernel=$KREL repo=$REPO_ROOT run_seconds=$RUN_SECONDS"

# Prerequisite: bcc must be importable, else nothing can load.
if ! "$PYTHON" -c "import bcc" 2>/dev/null; then
  echo "ERROR: python module 'bcc' not importable — install bpfcc-tools/python3-bpfcc." >&2
  exit 1
fi

# Generate filesystem + block + sendfile activity while the tracer runs.
generate_io() {
  local d; d="$(mktemp -d)"
  ( for i in $(seq 1 "$RUN_SECONDS"); do
      ls -R /usr >/dev/null 2>&1
      dd if=/dev/zero of="$d/f" bs=1M count=8 oflag=direct 2>/dev/null
      cat "$d/f" >/dev/null 2>&1
      cp "$d/f" "$d/f.copy" 2>/dev/null   # may use sendfile/copy_file_range
      sync
      rm -f "$d/f.copy"
      sleep 1
    done; rm -rf "$d" ) &
  echo $!
}

# run_one <label> <extra iotrc flags...>
run_one() {
  local label="$1"; shift
  local out; out="$(mktemp)"
  local tmphome; tmphome="$(mktemp -d)"   # iotrc writes under $TMPDIR/linux_trace
  echo
  echo "--- config: $label  (flags: $* ) ---"

  # Run the tracer in its own session so we can signal it cleanly.
  TMPDIR="$tmphome" setsid "$PYTHON" "$REPO_ROOT/iotrc.py" --no-upload "$@" \
      >"$out" 2>&1 &
  local pid=$!

  local iopid; iopid="$(generate_io)"
  sleep "$RUN_SECONDS"

  # Ask the tracer to stop (it installs SIGINT/SIGTERM handlers to flush).
  kill -INT "-$pid" 2>/dev/null || kill -INT "$pid" 2>/dev/null
  for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  kill -KILL "$pid" 2>/dev/null
  wait "$iopid" 2>/dev/null

  local ok=1

  # 1) BPF must have compiled & attached — look for the telltale failures.
  if grep -Eiq "failed to (load|attach|compile)|Traceback|verifier|Invalid argument|No such file or directory.*kprobe|Exception" "$out"; then
    echo "  [FAIL] error signatures in tracer output:"
    grep -Ei "failed to (load|attach|compile)|Traceback|verifier|Invalid argument|Exception" "$out" | sed 's/^/      /' | head -8
    ok=0
  else
    echo "  [ok] no load/attach/verifier errors"
  fi

  # 2) Trace shards must exist with the right header.
  local fsfile
  fsfile="$(find "$tmphome" -path '*/fs/fs_*' 2>/dev/null | head -1)"
  if [[ -n "$fsfile" ]]; then
    local hdr
    if [[ "$fsfile" == *.zst ]]; then
      hdr="$(zstd -dc "$fsfile" 2>/dev/null | head -1)"
    else
      hdr="$(head -1 "$fsfile")"
    fi
    if [[ "$hdr" == timestamp,operation,pid,* ]]; then
      echo "  [ok] fs shard written, header looks correct"
    else
      echo "  [FAIL] fs shard header unexpected: ${hdr:0:60}"
      ok=0
    fi
  else
    echo "  [FAIL] no fs trace shard produced under $tmphome"
    ok=0
  fi

  # Network config: confirm at least one nw_* shard appeared.
  if [[ "$*" == *--network* ]]; then
    if find "$tmphome" -path '*/nw_*' | grep -q .; then
      echo "  [ok] network shards produced"
    else
      echo "  [warn] --network set but no nw_* shards (may just be no traffic)"
    fi
  fi

  [[ "$ok" -eq 1 ]] && echo "  RESULT: PASS ($label)" || { echo "  RESULT: FAIL ($label)"; FAIL=1; }
  echo "  (tracer log: $out)"
  rm -rf "$tmphome"
}

run_one "default"
run_one "network"  --network
run_one "cache"    --cache

echo
if [[ "$FAIL" -eq 0 ]]; then
  echo "=== SMOKE TEST PASSED on $ARCH ($KREL) ==="
  exit 0
else
  echo "=== SMOKE TEST FAILED on $ARCH ($KREL) — inspect the tracer logs above ==="
  exit 1
fi
