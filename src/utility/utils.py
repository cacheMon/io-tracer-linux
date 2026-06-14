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

import csv
import io
import itertools
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


# Set once we've reported a missing ``zstandard`` install, so the
# uncompressed fallback is announced a single time rather than once per file
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
    back to leaving trace files uncompressed when the optional dependency is
    missing. The first time it is found missing a single warning is logged so
    the per-file fallback doesn't flood the logs across a trace run.
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
                    "kept uncompressed. Install it with 'pip install zstandard' "
                    "(or 'pip install -r requirements.txt') to enable compression.",
                )
        return None
    return zstandard


def compress_file_zstd(src: str, dst: str, level: int = ZSTD_LEVEL) -> bool:
    """
    Stream-compress a file to Zstandard.

    Args:
        src: Path to the source file
        dst: Path to write the compressed (.zst) output
        level: Zstandard compression level

    Returns:
        ``True`` if the file was compressed to ``dst``. If the optional
        ``zstandard`` library is unavailable nothing is written and ``False``
        is returned, so callers can fall back to the uncompressed source.
    """
    zstandard = zstandard_available()
    if zstandard is None:
        return False
    cctx = zstandard.ZstdCompressor(level=level)
    with open(src, "rb") as f_in, open(dst, "wb") as f_out:
        cctx.copy_stream(f_in, f_out)
    return True


def compress_log(input_file: str):
    """
    Compress a log file using Zstandard.

    Creates ``input_file.zst`` and removes the original when compression
    succeeds. If ``zstandard`` is unavailable the original file is left in
    place uncompressed.

    Args:
        input_file: Path to the file to compress
    """
    if compress_file_zstd(input_file, input_file + ".zst"):
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

def unlock_reward() -> None:
    """
    Unlock the reward by creating the marker file.
    """
    marker_path = get_reward_marker_path()
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.touch()

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
    
    Args:
        *fields: Variable number of field values
        
    Returns:
        str: Comma-separated values with proper escaping
        
    Example:
        >>> format_csv_row("name", "value,with,commas")
        'name,"value,with,commas"'
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator='')
    writer.writerow(fields)
    return output.getvalue()


if __name__ == "__main__":
    out = format_csv_row("field1", "field,with,commas", 'field "with" quotes', "simplefield")
    print(out)  # For demonstration purposes
