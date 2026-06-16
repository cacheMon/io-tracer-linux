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
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": platform.node(),
            "country": self.get_country_code()
        }
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
        self.wm.direct_write("os_info.json", json.dumps(os_info, indent=2))
