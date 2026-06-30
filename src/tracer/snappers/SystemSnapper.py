"""
SystemSnapper - Captures system hardware and software specifications.

This module provides the SystemSnapper class which gathers information
about the system including:
- CPU (brand, cores, frequency)
- GPU (detected NVIDIA cards)
- Memory (total and available)
- Storage devices
- Network interfaces
- Operating system version
- Geographic location (country code)

Output files (JSON format):
- cpu_info.json - CPU model, cores, frequency
- memory_info.json - Total RAM, available memory
- disk_info.json - Storage devices and partitions
- network_info.json - Network interfaces and addresses
- os_info.json - Kernel version, distribution, hostname

Example:
    snapper = SystemSnapper(writer_manager=wm)
    snapper.capture_spec_snapshot()  # Capture and write specs
"""

from ..WriterManager import WriteManager
from ...utility.utils import logger
import subprocess
import psutil
import platform
import shutil
import requests
import json
import os
import sys
import gzip
import tempfile
import traceback
from datetime import datetime


# Kernel config options that decide whether the BPF prober can compile, load
# (pass the verifier), and attach its kprobes/tracepoints. When the tracer
# cannot compile or fails to run, these are the first things a maintainer needs
# to see — e.g. a kernel built without CONFIG_DEBUG_INFO_BTF can't supply the
# BTF that BCC/CO-RE relies on, and CONFIG_BPF_SYSCALL=n disables BPF outright.
_BPF_KERNEL_CONFIG_KEYS = (
    "CONFIG_BPF",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_HAVE_EBPF_JIT",
    "CONFIG_BPF_EVENTS",
    "CONFIG_DEBUG_INFO",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_DEBUG_INFO_BTF_MODULES",
    "CONFIG_KPROBES",
    "CONFIG_KPROBE_EVENTS",
    "CONFIG_UPROBES",
    "CONFIG_FTRACE",
    "CONFIG_FUNCTION_TRACER",
    "CONFIG_TRACEPOINTS",
    "CONFIG_PERF_EVENTS",
    "CONFIG_HAVE_KPROBES",
    "CONFIG_NET_CLS_BPF",
    "CONFIG_CGROUP_BPF",
)


# ARM "CPU implementer" hex codes (from /proc/cpuinfo) → vendor name. Used only
# as a last-resort fallback when neither "model name" nor the device-tree model
# is available, so the recorded cpu brand is a vendor name rather than a raw code.
_ARM_IMPLEMENTERS = {
    "0x41": "ARM",
    "0x42": "Broadcom",
    "0x43": "Cavium",
    "0x44": "DEC",
    "0x46": "Fujitsu",
    "0x48": "HiSilicon",
    "0x49": "Infineon",
    "0x4d": "Motorola/Freescale",
    "0x4e": "NVIDIA",
    "0x50": "Ampere(APM)",
    "0x51": "Qualcomm",
    "0x53": "Samsung",
    "0x56": "Marvell",
    "0x61": "Apple",
    "0x66": "Faraday",
    "0x69": "Intel",
    "0xc0": "Ampere",
}


class SystemSnapper:
    """
    Captures system hardware and software specifications.
    
    This class gathers comprehensive information about the system
    to provide context for trace analysis. It collects data on:
    - CPU details (brand, cores, frequency)
    - GPU information (if available)
    - Memory statistics
    - Storage devices
    - OS version information
    - Geographic location
    
    Attributes:
        wm: WriteManager for outputting specification data
    """
    
    def __init__(self, writer_manager: WriteManager):
        """
        Initialize the SystemSnapper.
        
        Args:
            wm: WriteManager for outputting specification data
        """
        self.wm = writer_manager

    def get_cpu_brand(self) -> str | None:
        """
        Get the CPU brand/model name.
        
        Returns:
            str: CPU model name, or None if detection fails
        """
        system = platform.system()
        try:
            if system == "Linux":
                # x86 exposes a human-readable "model name"; ARM/aarch64 and some
                # other arches do not, so fall back to the device-tree model, then
                # the decoded ARM implementer/part fields, then platform.processor().
                fields = {}
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
                        if ":" in line:
                            k, v = line.split(":", 1)
                            fields.setdefault(k.strip(), v.strip())
                try:
                    # e.g. "NVIDIA Jetson ..." / SoC name on many ARM boards.
                    # Read in binary: the node is NUL-terminated and may contain
                    # non-UTF8 bytes, which would raise UnicodeDecodeError in text
                    # mode and defeat this fallback.
                    with open("/proc/device-tree/model", "rb") as f:
                        model = f.read().split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
                        if model:
                            return model
                except OSError:
                    pass
                # Last resort: synthesize a name from the ARM cpuinfo fields,
                # decoding the implementer code to a vendor name (the part number
                # stays hex — decoding it needs a per-vendor table).
                impl = fields.get("CPU implementer")
                part = fields.get("CPU part")
                if impl or part:
                    vendor = _ARM_IMPLEMENTERS.get((impl or "").lower(), impl or "ARM")
                    return f"{vendor} CPU" + (f" (part {part})" if part else "")
                return platform.processor() or None
            elif system == "Windows":
                out = subprocess.check_output("wmic cpu get Name", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip() and "Name" not in l]
                return lines[0] if lines else None
            else:
                return platform.processor()
        except Exception:
            return platform.processor()


    def get_gpu_brand(self) -> list[str]:
        """
        Get installed GPU brand names.
        
        Attempts to detect NVIDIA GPUs using nvidia-smi.
        
        Returns:
            list[str]: List of GPU names, empty if none detected
        """
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                text=True
            )
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            return []

    def get_storage_brands(self) -> list[str]:
        """
        Get installed storage device information.
        
        Detects storage devices (SSDs, HDDs) using lsblk on Linux
        or wmic on Windows.
        
        Returns:
            list[str]: List of storage device strings
        """
        system = platform.system()
        try:
            if system == "Linux" and shutil.which("lsblk"):
                out = subprocess.check_output("lsblk -d -o NAME,MODEL,SIZE", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # Skip header
            elif system == "Windows":
                out = subprocess.check_output("wmic diskdrive get Model,Size", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # Skip header
        except Exception:
            return []
        return []

    def get_country_code(self) -> str:
        """
        Get the country code based on IP geolocation.
        
        Attempts to determine the country using external IP lookup
        services as a fallback for identifying the user's location.
        
        Returns:
            str: Two-letter country code or "Unknown"
        """
        try:
            r = requests.get("https://ipapi.co/country_code/", timeout=5)
            if r.ok:
                return r.text.strip()
        except Exception:
            pass
        try:
            r = requests.get("http://ip-api.com/json/", timeout=5)
            if r.ok:
                return r.json().get("countryCode", "Unknown")
        except Exception:
            pass
        return "Unknown"

    def get_network_interfaces(self) -> dict:
        """
        Get network interface information.
        
        Returns:
            dict: Network interfaces with their addresses
        """
        interfaces = {}
        try:
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for iface, addrs in net_if_addrs.items():
                interface_info = {
                    "addresses": [],
                    "is_up": False,
                    "speed_mbps": None,
                    "mtu": None
                }
                
                for addr in addrs:
                    addr_info = {
                        "family": str(addr.family.name) if hasattr(addr.family, 'name') else str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    }
                    interface_info["addresses"].append(addr_info)
                
                if iface in net_if_stats:
                    stats = net_if_stats[iface]
                    interface_info["is_up"] = stats.isup
                    interface_info["speed_mbps"] = stats.speed
                    interface_info["mtu"] = stats.mtu
                
                interfaces[iface] = interface_info
        except Exception:
            pass
        return interfaces

    def get_disk_partitions(self) -> list:
        """
        Get disk partition information.
        
        Returns:
            list: Disk partitions with mount points and usage
        """
        partitions = []
        try:
            for part in psutil.disk_partitions(all=False):
                partition_info = {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "opts": part.opts
                }
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    partition_info["total_bytes"] = usage.total
                    partition_info["used_bytes"] = usage.used
                    partition_info["free_bytes"] = usage.free
                    partition_info["percent_used"] = usage.percent
                except Exception:
                    pass
                partitions.append(partition_info)
        except Exception:
            pass
        return partitions

    def capture_spec_snapshot(self):
        """
        Capture all system specifications and write to JSON files.
        
        Collects comprehensive system information and writes it
        to separate JSON files in the system_spec output directory:
        - cpu_info.json - CPU model, cores, frequency
        - memory_info.json - Total RAM, available memory
        - disk_info.json - Storage devices and partitions
        - network_info.json - Network interfaces and addresses
        - os_info.json - Kernel version, distribution, hostname
        """
        # CPU Info
        cpu_freq = psutil.cpu_freq()
        cpu_info = {
            "brand": self.get_cpu_brand(),
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
            "frequency_mhz": cpu_freq.current if cpu_freq else None,
            "frequency_min_mhz": cpu_freq.min if cpu_freq else None,
            "frequency_max_mhz": cpu_freq.max if cpu_freq else None
        }
        self.wm.direct_write("cpu_info.json", json.dumps(cpu_info, indent=2))

        # Memory Info
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        memory_info = {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "used_bytes": mem.used,
            "percent_used": mem.percent,
            "total_gb": round(mem.total / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
            "swap_total_bytes": swap.total,
            "swap_used_bytes": swap.used,
            "swap_free_bytes": swap.free
        }
        self.wm.direct_write("memory_info.json", json.dumps(memory_info, indent=2))

        # Disk Info
        disk_info = {
            "storage_devices": self.get_storage_brands(),
            "partitions": self.get_disk_partitions(),
            "gpus": self.get_gpu_brand()
        }
        self.wm.direct_write("disk_info.json", json.dumps(disk_info, indent=2))

        # Network Info
        network_info = {
            "interfaces": self.get_network_interfaces(),
            "hostname": platform.node()
        }
        self.wm.direct_write("network_info.json", json.dumps(network_info, indent=2))

        # OS Info
        os_info = self.get_os_info(include_country=True)
        self.wm.direct_write("os_info.json", json.dumps(os_info, indent=2))

    def get_os_info(self, include_country: bool = True) -> dict:
        """
        Collect operating system information.

        Args:
            include_country: When True, perform an IP-geolocation lookup for the
                country code. Set False to skip the network call — e.g. when
                dumping diagnostics on a build/run failure, where a slow or
                unreachable network must not delay or block the dump.

        Returns:
            dict: OS name/release/version/machine/hostname, plus a Linux
                distribution sub-dict (best effort) and, optionally, country.
        """
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": platform.node(),
        }
        if include_country:
            os_info["country"] = self.get_country_code()
        # Add distribution info for Linux
        if platform.system() == "Linux":
            try:
                import distro
                os_info["distribution"] = {
                    "name": distro.name(),
                    "version": distro.version(),
                    "codename": distro.codename()
                }
            except ImportError:
                # Fallback if distro package not available
                try:
                    with open("/etc/os-release") as f:
                        os_release = {}
                        for line in f:
                            if "=" in line:
                                key, value = line.strip().split("=", 1)
                                os_release[key] = value.strip('"')
                        os_info["distribution"] = {
                            "name": os_release.get("NAME", ""),
                            "version": os_release.get("VERSION_ID", ""),
                            "codename": os_release.get("VERSION_CODENAME", "")
                        }
                except Exception:
                    pass
        return os_info

    # ------------------------------------------------------------------ #
    # Failure diagnostics
    #
    # When the BPF prober cannot compile or the tracer fails to run, the
    # tooling previously exited with a generic "your device is incompatible"
    # message and nothing for a maintainer to act on. The methods below collect
    # as much of the OS / kernel / toolchain environment as possible — every
    # probe is individually guarded so one failure never aborts the rest — and
    # write it to a local file the user can attach when reporting the problem.
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe(fn, default=None):
        """Run a collector, returning its value or a ``{"_error": ...}`` marker.

        Keeps the diagnostics dump "best effort": a single probe that raises
        (missing /proc entry, permission error, absent tool) is recorded as an
        error instead of aborting the whole collection.
        """
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - diagnostics must never raise
            return {"_error": f"{type(e).__name__}: {e}"} if default is None else default

    @staticmethod
    def _read_text_file(path: str, max_bytes: int = 64 * 1024) -> str | None:
        """Read a (small) text file, returning ``None`` if it can't be read."""
        try:
            with open(path, "r", errors="replace") as f:
                return f.read(max_bytes).strip()
        except OSError:
            return None

    @staticmethod
    def _tool_version(cmd: list[str]) -> str | None:
        """Return the first line of ``cmd``'s output, or ``None`` if it fails.

        Used to capture compiler/linker versions (clang is what BCC shells out
        to when compiling the prober). Bounded by a short timeout so a missing
        or hung tool can't stall the diagnostics dump — this runs right before
        the process exits, and there are several of these calls in series, so
        the timeout is deliberately small to cap the worst-case exit latency.
        """
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=2
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = (out.stdout or out.stderr or "").strip()
        return text.splitlines()[0] if text else None

    # Substrings that mark a kernel-cmdline ``key=value`` token as carrying a
    # secret whose value should be redacted before it lands in the dump. The
    # cmdline itself is kept because it can reveal BPF-blocking settings
    # (lockdown=, lsm=, …) that are genuinely useful for diagnosis.
    _CMDLINE_SECRET_KEY_HINTS = ("secret", "token", "password", "passwd", "cred")

    @classmethod
    def _sanitize_cmdline(cls, cmdline: str | None) -> str | None:
        """Redact secret-looking ``key=value`` tokens from a kernel cmdline.

        Keeps every diagnostically useful parameter (lockdown, lsm, console, …)
        but replaces the *value* of any token whose key looks like a secret
        (e.g. a provisioning token occasionally passed at boot) with
        ``<redacted>``, so the dump the user is asked to share doesn't leak it.
        """
        if not cmdline:
            return cmdline
        out = []
        for token in cmdline.split():
            key, sep, _ = token.partition("=")
            if sep and any(h in key.lower() for h in cls._CMDLINE_SECRET_KEY_HINTS):
                out.append(f"{key}=<redacted>")
            else:
                out.append(token)
        return " ".join(out)

    def get_kernel_info(self) -> dict:
        """uname fields plus the raw kernel version/cmdline strings."""
        uname = os.uname()
        return {
            "sysname": uname.sysname,
            "nodename": uname.nodename,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "platform": platform.platform(),
            "proc_version": self._read_text_file("/proc/version"),
            # Boot cmdline can reveal BPF-blocking settings (e.g. lockdown=);
            # secret-looking tokens are redacted before it's recorded.
            "proc_cmdline": self._sanitize_cmdline(self._read_text_file("/proc/cmdline")),
            "libc": " ".join(platform.libc_ver()).strip() or None,
        }

    def get_btf_info(self) -> dict:
        """Whether the kernel ships BTF — required for BCC/CO-RE on modern setups."""
        btf_path = "/sys/kernel/btf/vmlinux"
        present = os.path.exists(btf_path)
        size = None
        if present:
            try:
                size = os.path.getsize(btf_path)
            except OSError:
                size = None
        return {"vmlinux_btf_present": present, "vmlinux_btf_bytes": size}

    def get_kernel_config(self) -> dict:
        """Curated BPF-relevant ``CONFIG_*`` values from the running kernel.

        Reads ``/proc/config.gz`` (gzip) when present, otherwise
        ``/boot/config-<release>``. Returns the source it used plus a value
        ("y"/"m"/"n"/...) for each key in :data:`_BPF_KERNEL_CONFIG_KEYS`;
        keys absent from the config are reported as ``None``.
        """
        release = os.uname().release
        raw = None
        source = None
        try:
            if os.path.exists("/proc/config.gz"):
                with gzip.open("/proc/config.gz", "rt", errors="replace") as f:
                    raw = f.read()
                source = "/proc/config.gz"
            else:
                boot_cfg = f"/boot/config-{release}"
                text = self._read_text_file(boot_cfg, max_bytes=2 * 1024 * 1024)
                if text is not None:
                    raw = text
                    source = boot_cfg
        except OSError:
            raw = None

        if raw is None:
            return {"source": None, "note": "kernel config not available", "values": {}}

        values: dict[str, str | None] = {k: None for k in _BPF_KERNEL_CONFIG_KEYS}
        wanted = set(_BPF_KERNEL_CONFIG_KEYS)
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key in wanted:
                values[key] = value
        return {"source": source, "values": values}

    def get_toolchain_info(self) -> dict:
        """Versions of the userspace pieces involved in building/loading BPF."""
        bcc_version = None
        try:
            import importlib.metadata as _md
            try:
                bcc_version = _md.version("bcc")
            except _md.PackageNotFoundError:
                bcc_version = None
        except Exception:  # noqa: BLE001 - metadata lookup is best effort
            bcc_version = None
        if bcc_version is None:
            try:
                import bcc as _bcc
                bcc_version = getattr(_bcc, "__version__", None)
            except Exception:  # noqa: BLE001 - bcc may be the thing that's broken
                bcc_version = None
        return {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "python_executable": sys.executable,
            "bcc_version": bcc_version,
            "clang_version": self._tool_version(["clang", "--version"]),
            "llc_version": self._tool_version(["llc", "--version"]),
            "gcc_version": self._tool_version(["gcc", "--version"]),
            "ld_version": self._tool_version(["ld", "--version"]),
        }

    def get_kernel_headers_info(self) -> dict:
        """Whether matching kernel headers/build tree are present (BCC fallback)."""
        release = os.uname().release
        build_link = f"/lib/modules/{release}/build"
        headers_dir = f"/usr/src/linux-headers-{release}"
        build_target = None
        if os.path.islink(build_link):
            try:
                build_target = os.readlink(build_link)
            except OSError:
                build_target = None
        return {
            "modules_build_path": build_link,
            "modules_build_present": os.path.exists(build_link),
            "modules_build_symlink_target": build_target,
            "usr_src_headers_path": headers_dir,
            "usr_src_headers_present": os.path.exists(headers_dir),
        }

    def get_tracefs_info(self) -> dict:
        """debugfs/tracefs availability and the cmd_flags tracepoint probe.

        ``block_rq_complete``'s ``cmd_flags`` field is what IOTracer keys
        ``-DHAS_CMD_FLAGS`` off, so its presence (or absence) here mirrors a
        compile-time branch and is useful when a build fails.
        """
        debug_tracing = "/sys/kernel/debug/tracing"
        tracefs = "/sys/kernel/tracing"
        tp_format = f"{debug_tracing}/events/block/block_rq_complete/format"
        has_cmd_flags = None
        if os.path.exists(tp_format):
            fmt = self._read_text_file(tp_format)
            has_cmd_flags = ("cmd_flags" in fmt) if fmt is not None else None
        return {
            "debugfs_tracing_mounted": os.path.isdir(debug_tracing),
            "tracefs_mounted": os.path.isdir(tracefs),
            "block_rq_complete_has_cmd_flags": has_cmd_flags,
        }

    def get_cpu_info(self) -> dict:
        """CPU brand and core counts (no frequency probe — kept dependency-light)."""
        return {
            "brand": self.get_cpu_brand(),
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
        }

    def get_memory_info(self) -> dict:
        """Total/available RAM, for context on a verifier/OOM-style failure."""
        mem = psutil.virtual_memory()
        return {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "total_gb": round(mem.total / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
        }

    def collect_diagnostics(
        self,
        error: BaseException | None = None,
        attempted_cflags: list[str] | None = None,
        bpf_file: str | None = None,
        context: str | None = None,
    ) -> dict:
        """
        Gather as much OS / kernel / toolchain context as possible.

        Built to be robust on exactly the broken hosts it is meant to diagnose:
        every section is collected through :meth:`_safe`, so a probe that raises
        is recorded as an error rather than aborting the dump. The result is
        plain JSON-serializable data.

        Args:
            error: The exception that triggered the dump (compile/load/attach
                failure), recorded with its traceback.
            attempted_cflags: The cflags BCC was invoked with, if known.
            bpf_file: Path to the BPF C source that failed to build.
            context: Short human description of what failed.

        Returns:
            dict: Structured diagnostics (see the on-disk file for the layout).
        """
        diagnostics: dict = {
            "io_tracer_diagnostics": {
                "generated_at": datetime.now().isoformat(),
                "context": context or "BPF program could not compile or the tracer failed to run",
                "note": (
                    "Collected automatically because the IO Tracer could not "
                    "compile or load its eBPF program on this host. Share this "
                    "file with the maintainers so they can diagnose the "
                    "incompatibility."
                ),
            },
        }

        if error is not None:
            diagnostics["error"] = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": "".join(
                    traceback.format_exception(type(error), error, error.__traceback__)
                ).strip(),
            }

        diagnostics["attempt"] = {
            "bpf_source": bpf_file,
            "cflags": list(attempted_cflags) if attempted_cflags is not None else None,
            "euid": self._safe(os.geteuid, default=None),
        }

        diagnostics["bpf_environment"] = {
            "kernel": self._safe(self.get_kernel_info),
            "btf": self._safe(self.get_btf_info),
            "kernel_config": self._safe(self.get_kernel_config),
            "toolchain": self._safe(self.get_toolchain_info),
            "kernel_headers": self._safe(self.get_kernel_headers_info),
            "tracefs": self._safe(self.get_tracefs_info),
        }

        diagnostics["system"] = {
            "os": self._safe(lambda: self.get_os_info(include_country=False)),
            "cpu": self._safe(self.get_cpu_info),
            "memory": self._safe(self.get_memory_info),
        }

        return diagnostics

    def dump_failure_diagnostics(
        self,
        error: BaseException | None = None,
        attempted_cflags: list[str] | None = None,
        bpf_file: str | None = None,
        context: str | None = None,
        dest_dir: str | None = None,
    ) -> str | None:
        """
        Collect diagnostics, write them to a local JSON file, and print a summary.

        Never raises: this runs on the failure path (right before the process
        exits), so any error here is swallowed rather than masking the original
        BPF failure. The file is written to ``dest_dir`` if given, else the
        current working directory, else the system temp dir — the first that is
        writable wins.

        Returns:
            str | None: Path to the diagnostics file, or ``None`` if it could
            not be written anywhere (the summary is still printed).
        """
        try:
            diagnostics = self.collect_diagnostics(
                error=error,
                attempted_cflags=attempted_cflags,
                bpf_file=bpf_file,
                context=context,
            )
        except Exception as e:  # noqa: BLE001 - diagnostics must never raise
            diagnostics = {"_collect_error": f"{type(e).__name__}: {e}"}

        # default=str so anything unexpectedly non-serializable still dumps.
        try:
            text = json.dumps(diagnostics, indent=2, default=str)
        except Exception:  # noqa: BLE001
            text = repr(diagnostics)

        filename = f"io-tracer-os-info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = None
        candidates = [dest_dir, os.getcwd(), tempfile.gettempdir()]
        for directory in candidates:
            if not directory:
                continue
            try:
                candidate = os.path.join(directory, filename)
                with open(candidate, "w") as f:
                    f.write(text)
                path = candidate
                break
            except OSError:
                continue

        self._print_diagnostics_summary(diagnostics, path)
        return path

    @staticmethod
    def _print_diagnostics_summary(diagnostics: dict, path: str | None) -> None:
        """Print a short, human-readable highlight of the collected diagnostics."""
        def _get(d, *keys):
            for k in keys:
                if not isinstance(d, dict):
                    return None
                d = d.get(k)
            return d

        print("\n--- IO Tracer OS information (build/run failure) ---")
        kernel = _get(diagnostics, "bpf_environment", "kernel") or {}
        os_sec = _get(diagnostics, "system", "os") or {}
        distro = os_sec.get("distribution") if isinstance(os_sec, dict) else None
        btf = _get(diagnostics, "bpf_environment", "btf") or {}
        tool = _get(diagnostics, "bpf_environment", "toolchain") or {}
        err = diagnostics.get("error") or {}

        def _line(label, value):
            if value not in (None, "", {}):
                print(f"  {label}: {value}")

        _line("Kernel", kernel.get("release"))
        if isinstance(distro, dict):
            name = " ".join(
                str(v) for v in (distro.get("name"), distro.get("version")) if v
            ).strip()
            _line("Distribution", name or None)
        _line("Architecture", kernel.get("machine"))
        _line("BTF (vmlinux)", "present" if btf.get("vmlinux_btf_present") else "MISSING")
        _line("clang", tool.get("clang_version"))
        _line("bcc", tool.get("bcc_version"))
        if err:
            _line("Error", f"{err.get('type')}: {err.get('message')}")

        if path:
            print(f"\n  Full diagnostics written to: {path}")
        else:
            print("\n  (could not write the diagnostics file to disk)")
        print(
            "  Please send this information to io-tracer@googlegroups.com so we "
            "can help.\n"
        )
