"""
Utility functions for IO Tracer.

This module provides commonly used utility functions including:
- Hashing for anonymization
- Logging
- CSV formatting
- Network address conversion
- Machine ID capture
- Reward code management
- File compression

Example:
    from src.utility.utils import logger, format_csv_row, simple_hash
    
    logger("info", "Processing complete")
    row = format_csv_row("field1", "field2", "field3")
    hashed = simple_hash("sensitive_data")
"""

import gzip
import itertools
import shutil
import sys
import threading
from pathlib import Path
import os
import time
import datetime
import hashlib
import socket
import struct
import subprocess


# Global cache for hash values to avoid repeated computation
_HASH_CACHE: dict[str, str] = {}

def hash_filename_in_path(path, hash_length: int = 12) -> str:
    """
    Hash a filename while preserving the directory structure.
    
    Takes a Path object, hashes the filename portion, and returns
    a new path with the hashed filename in the same directory.
    
    Args:
        path: Path object containing the filename to hash
        hash_length: Number of characters from hash to use (default: 12)
        
    Returns:
        str: New path with hashed filename
        
    Example:
        >>> from pathlib import Path
        >>> hash_filename_in_path(Path("/home/user/document.txt"))
        '/home/user/abc123def456.txt'
    """
    directory = path.parent
    filename = path.name
    
    name_without_ext = path.stem
    extension = path.suffix
    
    hash_obj = hashlib.sha256()
    hash_obj.update(name_without_ext.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    
    truncated_hash = full_hash[:hash_length]
    
    new_filename = truncated_hash + extension
    new_filepath = directory / new_filename
    
    return str(new_filepath)

def hash_component(name: str, keep_ext: bool = True, length: int = 12) -> str:
    """
    Hash a string component (filename or path segment).
    
    Args:
        name: String to hash
        keep_ext: Whether to preserve extension (default: True)
        length: Number of hash characters to use (default: 12)
        
    Returns:
        str: Hashed string, optionally with extension preserved
        
    Example:
        >>> hash_component("document.txt")
        'abc123def456.txt'
        >>> hash_component("document.txt", keep_ext=False)
        'abc123def456'
    """
    if keep_ext and '.' in name and not name.startswith('.'):
        stem, ext = os.path.splitext(name)
        key = f"{stem}|{length}"
        if key not in _HASH_CACHE:
            _HASH_CACHE[key] = hashlib.sha256(stem.encode("utf-8")).hexdigest()[:length]
        return _HASH_CACHE[key] + ext
    else:
        key = f"{name}|{length}"
        if key not in _HASH_CACHE:
            _HASH_CACHE[key] = hashlib.sha256(name.encode("utf-8")).hexdigest()[:length]
        return _HASH_CACHE[key]

def hash_rel_path(rel: Path, keep_ext: bool = True, length: int = 12) -> Path:
    """
    Hash all but the first two components of a relative path.
    
    Preserves the first two path segments (e.g., "/" or "/home/user")
    and hashes the remaining components for anonymization.
    
    Args:
        rel: Relative Path object to hash
        keep_ext: Whether to preserve extensions (default: True)
        length: Hash length for each component (default: 12)
        
    Returns:
        Path: New path with hashed components
        
    Example:
        >>> from pathlib import Path
        >>> hash_rel_path(Path("/home/user/documents/file.txt"))
        Path('/home/user/abc123def456/file.txt')
    """
    parts = list(rel.parts)
    
    # Keep first two components (e.g., "/" and "home")
    unhashed_parts = parts[:2] if len(parts) >= 2 else parts
    
    # Hash remaining components
    hashed_parts = unhashed_parts + [
        hash_component(p, keep_ext=keep_ext, length=length) 
        for p in parts[2:]
    ]
    
    return Path(*hashed_parts)

def anonymize_path(path, keep_ext: bool = True, length: int = 12) -> str:
    """Anonymize a filesystem path by hashing EVERY component.

    Hashes the basename and all directory components, preserving only a leading
    root separator ("/") and (optionally) file extensions. Unlike
    ``hash_rel_path`` — which keeps the first two components in cleartext — this
    never leaves a component unhashed, so bare basenames (e.g. ``"id_rsa"``) and
    short relative paths (e.g. ``"proj/key.pem"``) are still fully anonymized.
    Directory structure (depth) is preserved.

    Example:
        >>> anonymize_path("/home/alice/.ssh/id_rsa")
        '/<h>/<h>/<h>/<h>'
        >>> anonymize_path("id_rsa")
        '<h>'
    """
    parts = list(Path(path).parts)
    if not parts:
        return path
    out = []
    for i, comp in enumerate(parts):
        if i == 0 and comp == os.sep:
            out.append(comp)  # keep the leading "/" so absolute stays absolute
        else:
            out.append(hash_component(comp, keep_ext=keep_ext, length=length))
    return str(Path(*out))

def simple_hash(content: str, length: int = 12) -> str:
    """
    Create a simple SHA-256 hash of a string.
    
    Args:
        content: String to hash
        length: Number of hash characters to return (default: 12)
        
    Returns:
        str: Truncated hexadecimal hash
        
    Example:
        >>> simple_hash("Hello, World!")
        'a591a6d40bf'
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(content.encode('utf-8'))
    full_hash = hash_obj.hexdigest()
    truncated_hash = full_hash[:length]
    return truncated_hash


def logger(error_scale: str, string: str, timestamp: bool = False):
    """
    Print a formatted log message.
    
    Args:
        error_scale: Log level/category (e.g., "info", "error", "warning")
        string: Message to log
        timestamp: Whether to include timestamp (default: False)
        
    Example:
        >>> logger("info", "Application started")
        [INFO] Application started
        >>> logger("error", "Failed to open file", timestamp=True)
        [ERROR] [2024-01-15 10:30:45.123456] Failed to open file
    """
    timestamp_seconds = time.time()
    dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
    formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
    if error_scale == "warning":
        logo = "[WARN]"
    elif error_scale == "error":
        logo = "[ERROR]"
    elif error_scale == "info":
        logo = "[INFO]"
    else:
        logo = f"[{error_scale}]"

    if timestamp:
        timestamp_seconds = time.time()
        dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
        formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
        logo += f" [{formatted_time}]" 
    print(logo + " " + string)

# Zstandard compression level. 3 is the library default — a good
# speed/ratio tradeoff for streaming large trace logs.
ZSTD_LEVEL = 3

# gzip compression level used for the standard-library fallback when the
# optional ``zstandard`` package is unavailable. 6 is gzip's default — a
# reasonable speed/ratio tradeoff for streaming large trace logs.
GZIP_LEVEL = 6


# Set once we've reported a missing ``zstandard`` install, so the
# gzip fallback is announced a single time rather than once per file
# across a whole trace run. Guarded by a lock because the writer's parallel
# stream threads can reach this concurrently.
_zstandard_missing_warned = False
_zstandard_warn_lock = threading.Lock()


def require_zstandard():
    """
    Import and return the optional ``zstandard`` module.

    Imported lazily so environments that never compress (and the pure-Python
    unit tests) don't need the dependency at import time. Raises a clear,
    actionable error if it is missing.
    """
    try:
        import zstandard
    except ModuleNotFoundError as e:
        raise ModuleNotFoundError(
            "The 'zstandard' library is required for Zstandard compression but "
            "is not installed. Install it with 'pip install zstandard'."
        ) from e
    return zstandard


def zstandard_available():
    """
    Return the ``zstandard`` module if installed, otherwise ``None``.

    Unlike :func:`require_zstandard` this never raises, letting callers fall
    back to gzip (standard library) when the optional dependency is missing.
    The first time it is found missing a single warning is logged so the
    per-file fallback doesn't flood the logs across a trace run.
    """
    global _zstandard_missing_warned
    try:
        # Catch ImportError (not just ModuleNotFoundError) so a zstandard that
        # is installed but fails to load — e.g. a broken C-extension or missing
        # shared library — also falls back gracefully instead of crashing.
        import zstandard
    except ImportError:
        with _zstandard_warn_lock:
            if not _zstandard_missing_warned:
                _zstandard_missing_warned = True
                logger(
                    "warning",
                    "The 'zstandard' library is not installed; trace files will be "
                    "compressed with gzip (.gz) instead. Install it with "
                    "'pip install zstandard' (or 'pip install -r requirements.txt') "
                    "for faster, smaller Zstandard (.zst) output.",
                )
        return None
    return zstandard


def compressed_suffix() -> str:
    """Return the file extension of the active log-compression codec.

    ``.zst`` when the optional ``zstandard`` library is available, otherwise
    ``.gz`` for the gzip standard-library fallback.
    """
    return ".zst" if zstandard_available() is not None else ".gz"


def compress_file(src: str, level: int | None = None) -> str | None:
    """
    Stream-compress a file with the best available codec.

    Prefers Zstandard (``<src>.zst``); when the optional ``zstandard`` library
    is unavailable, falls back to gzip (``<src>.gz``) from the standard library
    so trace files are still compressed rather than left raw. The source file
    is left in place — callers remove it after the compressed output has been
    handed off (e.g. queued for upload).

    Args:
        src: Path to the source file
        level: Compression level; defaults to the codec's tuned level
            (:data:`ZSTD_LEVEL` for Zstandard, :data:`GZIP_LEVEL` for gzip).

    Returns:
        Path to the compressed output, or ``None`` if compression failed (so
        callers can fall back to the uncompressed source).
    """
    zstandard = zstandard_available()
    if zstandard is not None:
        dst = src + ".zst"
    else:
        # gzip fallback — always available in the standard library.
        dst = src + ".gz"

    try:
        if zstandard is not None:
            cctx = zstandard.ZstdCompressor(level=ZSTD_LEVEL if level is None else level)
            with open(src, "rb") as f_in, open(dst, "wb") as f_out:
                cctx.copy_stream(f_in, f_out)
        else:
            with open(src, "rb") as f_in, gzip.open(
                dst, "wb", compresslevel=GZIP_LEVEL if level is None else level
            ) as f_out:
                shutil.copyfileobj(f_in, f_out)
        return dst
    except Exception as e:
        # Don't leave a half-written archive behind, and signal failure so the
        # caller keeps the uncompressed source rather than losing trace data.
        logger("error", f"Failed to compress {src}: {e}")
        try:
            if os.path.exists(dst):
                os.remove(dst)
        except OSError:
            pass
        return None


def compress_log(input_file: str):
    """
    Compress a log file, preferring Zstandard and falling back to gzip.

    Creates ``input_file.zst`` (or ``input_file.gz`` when ``zstandard`` is
    unavailable) and removes the original once compression succeeds.

    Args:
        input_file: Path to the file to compress
    """
    out = compress_file(input_file)
    if out is not None and out != input_file:
        os.remove(input_file)

def capture_machine_id() -> str:
    """
    Capture and hash the machine's unique identifier.
    
    Reads /etc/machine-id and returns a 16-character hash.
    This provides a consistent anonymous machine identifier.
    
    Returns:
        str: 16-character hash of the machine ID
        
    Example:
        >>> capture_machine_id()
        'a1b2c3d4e5f6g7h8'
    """
    with open("/etc/machine-id") as f:
        machine_id = f.read().strip()
        return simple_hash(machine_id, 16)

# Reward code for Prolific submissions
REWARD_CODE = "CKXDRTBX"

def get_reward_marker_path() -> Path:
    """
    Get the path to the reward unlock marker file.
    
    Returns:
        Path: ~/.io-tracer/.reward_unlocked
    """
    return Path.home() / ".io-tracer" / ".reward_unlocked"

def is_reward_unlocked() -> bool:
    """
    Check if the reward has been unlocked.
    
    Returns:
        bool: True if the reward marker file exists
    """
    return get_reward_marker_path().exists()

def unlock_reward() -> bool:
    """
    Unlock the reward by creating the marker file.

    Returns:
        bool: True if this is a fresh unlock, False if already unlocked before.
    """
    marker_path = get_reward_marker_path()
    if marker_path.exists():
        return False
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.touch()
    return True

def print_reward_notification() -> None:
    """Print a one-time banner when the reward is freshly unlocked."""
    _GREEN = "\033[1;32m"
    _R = "\033[0m"
    banner = (
        f"\n{_GREEN}{'*' * 56}{_R}\n"
        f"{_GREEN}  Reward Unlocked! Prolific submission code:{_R}\n"
        f"{_GREEN}  {REWARD_CODE}{_R}\n"
        f"{_GREEN}  Run: sudo python iotrc.py --reward to view again.{_R}\n"
        f"{_GREEN}{'*' * 56}{_R}\n"
    )
    print(banner)

def get_reward_code() -> str | None:
    """
    Get the reward code if unlocked.
    
    Returns:
        str: Reward code if unlocked, None otherwise
    """
    if is_reward_unlocked():
        return REWARD_CODE
    return None

def to_bytes16(x) -> bytes:
    """
    Convert various representations to 16 bytes.
    
    Handles:
    - bytes/bytearray (must be 16 bytes)
    - tuple of two 64-bit integers
    - integer
    
    Args:
        x: Value to convert
        
    Returns:
        bytes: 16-byte representation
        
    Raises:
        ValueError: If bytearray length is wrong
        TypeError: If type is unsupported
    """
    if isinstance(x, (bytes, bytearray)):
        if len(x) != 16:
            raise ValueError(f"expected 16 bytes, got {len(x)}")
        return bytes(x)
    try:
        b = bytes(bytearray(x))
        if len(b) == 16:
            return b
    except TypeError:
        pass
    if isinstance(x, tuple) and len(x) == 2 and all(isinstance(v, int) for v in x):
        return struct.pack(">QQ", x[0], x[1])
    if isinstance(x, int):
        return x.to_bytes(16, "big")
    raise TypeError(f"unsupported type for IPv6 addr: {type(x)}")

def inet6_from_event(v6) -> str:
    """
    Convert IPv6 address from event format to string.
    
    Args:
        v6: IPv6 address tuple or bytes
        
    Returns:
        str: IPv6 address in standard notation
    """
    return socket.inet_ntop(socket.AF_INET6, to_bytes16(v6))

def inet4_from_event(v4_u32) -> str:
    """
    Convert IPv4 address from uint32 to string.
    
    Args:
        v4_u32: 32-bit unsigned integer representing IPv4 address
        
    Returns:
        str: IPv4 address in dotted decimal notation
    """
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", int(v4_u32)))

def get_current_tag() -> str:
    """
    Get the current git tag for the application.
    
    Returns:
        str: Git tag with dots replaced by underscores, or "no_tags"
    """
    try:
        tag = subprocess.check_output(
            ['git', 'describe', '--tags', '--abbrev=0'],
            text=True
        ).strip()
        return tag.replace('.', '_')
    except subprocess.CalledProcessError:
        return "no_tags"

def run_with_spinner(label: str, fn):
    done = threading.Event()
    exc_box: list[BaseException | None] = [None]
    result_box: list = [None]

    _DARK_SALMON = "\033[38;2;233;150;122m"
    _YELLOW      = "\033[38;2;255;215;0m"
    _RESET       = "\033[0m"

    def _spin():
        frames = itertools.cycle(["|", "/", "-", "\\"])
        while not done.is_set():
            sys.stderr.write(f"\r{_DARK_SALMON}{label}...{_RESET} {_YELLOW}{next(frames)}{_RESET} ")
            sys.stderr.flush()
            time.sleep(0.1)

    def _worker():
        try:
            result_box[0] = fn()
        except Exception as e:
            exc_box[0] = e
        finally:
            done.set()

    t_spin = threading.Thread(target=_spin, daemon=True)
    t_work = threading.Thread(target=_worker, daemon=True)
    t_spin.start()
    t_work.start()
    t_work.join()
    t_spin.join()
    _GREEN = "\033[38;2;0;200;100m"
    sys.stderr.write(f"\r{_DARK_SALMON}{label}...{_RESET} {_GREEN}done{_RESET}\n")
    sys.stderr.flush()
    if exc_box[0]:
        raise exc_box[0]
    return result_box[0]


def format_csv_row(*fields) -> str:
    """
    Format fields as a CSV row without trailing newline.

    Hot path: called once per traced event (millions of times per trace), so it
    avoids the per-row ``io.StringIO`` + ``csv.writer`` allocation the stdlib
    ``csv`` module would incur. The quoting rules reproduce Python's csv default
    dialect exactly (``QUOTE_MINIMAL``): a field is quoted only when it contains
    the delimiter ``,``, the quote char ``"``, or a line break (``\\n``/``\\r``),
    embedded quotes are doubled, and ``None`` becomes an empty field.

    Args:
        *fields: Variable number of field values

    Returns:
        str: Comma-separated values with proper escaping

    Example:
        >>> format_csv_row("name", "value,with,commas")
        'name,"value,with,commas"'
    """
    parts = []
    append = parts.append
    for f in fields:
        if f is None:
            append("")
        elif type(f) is str:
            # QUOTE_MINIMAL: only quote when a special char is present.
            if ('"' in f) or ("," in f) or ("\n" in f) or ("\r" in f):
                append('"' + f.replace('"', '""') + '"')
            else:
                append(f)
        else:
            # Non-str (int/float/bool): str() never yields a CSV-special char,
            # so it can be appended without the quoting scan. Matches csv, which
            # str()s non-string fields.
            append(str(f))
    # csv quotes a lone empty field as "" so a one-empty-field row stays
    # distinguishable from a zero-field (empty) row on read-back.
    if len(parts) == 1 and parts[0] == "":
        return '""'
    return ",".join(parts)


# Thresholds for auto-enabling the higher-overhead tracing subsystems based on
# host resources. The page-cache and network probes add CPU and DRAM overhead,
# so they are only switched on automatically when the machine has headroom to
# spare. Tune these in one place rather than scattering magic numbers.
AUTO_TRACE_MIN_LOGICAL_CORES = 8      # cores needed to absorb extra probe work
AUTO_TRACE_MIN_TOTAL_RAM_GB = 16.0    # total DRAM for the larger event buffers
AUTO_TRACE_MIN_AVAIL_RAM_GB = 2.0     # free DRAM headroom at start-of-trace
AUTO_TRACE_MIN_NET_SPEED_MBPS = 10    # a link fast enough (>=10 Mbps) to be worth tracing


def detect_host_resources() -> dict:
    """
    Sample the host's CPU, DRAM and network capacity.

    Uses psutil (already a runtime dependency). Returns a dict with keys
    ``logical_cores``, ``total_ram_gb``, ``available_ram_gb`` and
    ``max_net_speed_mbps``. Any field that cannot be determined is reported as
    0 so callers can treat it as "not enough" rather than crashing.

    The network figure is the fastest reported speed among up, non-loopback
    interfaces; interfaces that report an unknown speed (0) are ignored.
    """
    resources = {
        "logical_cores": 0,
        "total_ram_gb": 0.0,
        "available_ram_gb": 0.0,
        "max_net_speed_mbps": 0,
    }
    try:
        import psutil

        # psutil can return None in some virtualized/containerized environments;
        # fall back to the stdlib count before giving up.
        resources["logical_cores"] = psutil.cpu_count(logical=True) or os.cpu_count() or 0

        mem = psutil.virtual_memory()
        resources["total_ram_gb"] = mem.total / (1024 ** 3)
        resources["available_ram_gb"] = mem.available / (1024 ** 3)

        speeds = [
            stats.speed
            for name, stats in psutil.net_if_stats().items()
            if stats.isup and name != "lo" and stats.speed and stats.speed > 0
        ]
        resources["max_net_speed_mbps"] = max(speeds) if speeds else 0
    except Exception:
        # Leave the conservative zero defaults in place; the evaluator will
        # then decline to auto-enable anything.
        pass
    return resources


def evaluate_resource_tracing(
    logical_cores: int,
    total_ram_gb: float,
    available_ram_gb: float,
    max_net_speed_mbps: int,
) -> dict:
    """
    Decide whether cache/network tracing is advisable for the given resources.

    Pure function (no I/O) so it is easy to unit test. Page-cache tracing is
    gated on CPU and DRAM; network tracing additionally requires a fast enough
    link to be worthwhile. Returns a dict with boolean ``enable_cache`` /
    ``enable_network`` plus the individual ``cpu_ok`` / ``ram_ok`` / ``net_ok``
    checks for logging.
    """
    cpu_ok = (logical_cores or 0) >= AUTO_TRACE_MIN_LOGICAL_CORES
    ram_ok = (
        (total_ram_gb or 0) >= AUTO_TRACE_MIN_TOTAL_RAM_GB
        and (available_ram_gb or 0) >= AUTO_TRACE_MIN_AVAIL_RAM_GB
    )
    net_ok = (max_net_speed_mbps or 0) >= AUTO_TRACE_MIN_NET_SPEED_MBPS
    return {
        "cpu_ok": cpu_ok,
        "ram_ok": ram_ok,
        "net_ok": net_ok,
        "enable_cache": cpu_ok and ram_ok,
        "enable_network": cpu_ok and ram_ok and net_ok,
    }


def auto_select_tracing(
    trace_cache: bool, trace_network: bool, verbose: bool = False
) -> tuple[bool, bool]:
    """
    Auto-enable cache/network tracing when the host has spare resources.

    Page-cache tracing is the highest-volume stream (every page add/dirty/
    writeback/evict) and costs ~1 CPU core on a busy box, so it is auto-enabled
    only on a capable host — at least ``AUTO_TRACE_MIN_LOGICAL_CORES`` cores
    (8) and ``AUTO_TRACE_MIN_TOTAL_RAM_GB`` GB RAM (16) — where that overhead is
    affordable. Network tracing additionally requires a fast enough link.

    Explicit opt-ins are always honored: a flag already set to True is never
    turned back off; this only switches a subsystem on, never off.

    Args:
        trace_cache: whether page-cache tracing was explicitly requested
        trace_network: whether network tracing was explicitly requested
        verbose: when True, log the detected resources and the decision

    Returns:
        (trace_cache, trace_network) after applying the auto policy.
    """
    resources = detect_host_resources()
    decision = evaluate_resource_tracing(
        resources["logical_cores"],
        resources["total_ram_gb"],
        resources["available_ram_gb"],
        resources["max_net_speed_mbps"],
    )

    # Auto-enable cache on a capable host (>=8 cores and >=16 GB RAM); network
    # additionally requires a fast link. Explicit flags are never turned off.
    auto_cache = trace_cache or decision["enable_cache"]
    auto_network = trace_network or decision["enable_network"]

    if verbose:
        logger(
            "info",
            "Host resources: "
            f"{resources['logical_cores']} logical cores, "
            f"{resources['total_ram_gb']:.1f} GB RAM total / "
            f"{resources['available_ram_gb']:.1f} GB available, "
            f"{resources['max_net_speed_mbps']} Mbps fastest link "
            f"(thresholds: >={AUTO_TRACE_MIN_LOGICAL_CORES} cores, "
            f">={AUTO_TRACE_MIN_TOTAL_RAM_GB:.0f} GB total / "
            f">={AUTO_TRACE_MIN_AVAIL_RAM_GB:.0f} GB free, "
            f">={AUTO_TRACE_MIN_NET_SPEED_MBPS} Mbps).",
        )
        if auto_network and not trace_network:
            logger("info", "Auto-enabled network tracing (host has enough CPU, DRAM and network).")
        if not auto_network:
            logger("info", "Network tracing left off (insufficient CPU/DRAM/network headroom).")
        if auto_cache and not trace_cache:
            logger("info", "Auto-enabled page-cache tracing (host has >=8 cores and >=16 GB RAM).")
        elif auto_cache:
            logger("info", "Page-cache tracing enabled (--cache).")
        else:
            logger("info", "Page-cache tracing left off (insufficient CPU/DRAM headroom for the highest-volume stream).")

    return auto_cache, auto_network


if __name__ == "__main__":
    out = format_csv_row("field1", "field,with,commas", 'field "with" quotes', "simplefield")
    print(out)  # For demonstration purposes
