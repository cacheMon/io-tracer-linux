# System Snapshot

**Description:** Captures hardware and software specifications for trace context.

**Location:** `linux_trace_v4_test/{MACHINE_ID}/{TIMESTAMP}/system_spec/`

**Collection Method:**
- Queries system information once at trace start
- Uses `psutil`, `platform`, and subprocess calls
- Attempts IP geolocation for country detection

## Output Files

System specifications are captured in separate JSON files:

| File | Description |
|------|-------------|
| `cpu_info.json` | CPU model, cores, frequency |
| `memory_info.json` | Total RAM, available memory, swap |
| `disk_info.json` | Storage devices and partitions |
| `network_info.json` | Network interfaces and addresses |
| `os_info.json` | Kernel version, distribution, hostname |

---

## cpu_info.json

CPU hardware specifications.

| Field | Type | Description |
|-------|------|-------------|
| `brand` | `string` | CPU model name (from `/proc/cpuinfo` on Linux, `wmic` on Windows); `null` if unavailable |
| `cores_logical` | `integer` | Number of logical CPU cores (including hyperthreads) |
| `cores_physical` | `integer` | Number of physical CPU cores |
| `frequency_mhz` | `float` | Current CPU frequency in MHz; `null` if unavailable |
| `frequency_min_mhz` | `float` | Minimum CPU frequency in MHz; `null` if unavailable |
| `frequency_max_mhz` | `float` | Maximum CPU frequency in MHz; `null` if unavailable |

### Example

```json
{
  "brand": "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
  "cores_logical": 16,
  "cores_physical": 8,
  "frequency_mhz": 2900.0,
  "frequency_min_mhz": 800.0,
  "frequency_max_mhz": 4800.0
}
```

---

## memory_info.json

System memory statistics.

| Field | Type | Description |
|-------|------|-------------|
| `total_bytes` | `integer` | Total system RAM in bytes |
| `available_bytes` | `integer` | Currently available RAM in bytes |
| `used_bytes` | `integer` | Used RAM in bytes |
| `percent_used` | `float` | Memory usage percentage |
| `total_gb` | `float` | Total system RAM in GB (rounded to 2 decimals) |
| `available_gb` | `float` | Available RAM in GB (rounded to 2 decimals) |
| `swap_total_bytes` | `integer` | Total swap space in bytes |
| `swap_used_bytes` | `integer` | Used swap space in bytes |
| `swap_free_bytes` | `integer` | Free swap space in bytes |

### Example

```json
{
  "total_bytes": 17062027264,
  "available_bytes": 9073254400,
  "used_bytes": 7988772864,
  "percent_used": 46.8,
  "total_gb": 15.89,
  "available_gb": 8.45,
  "swap_total_bytes": 2147483648,
  "swap_used_bytes": 0,
  "swap_free_bytes": 2147483648
}
```

---

## disk_info.json

Storage devices and partition information.

| Field | Type | Description |
|-------|------|-------------|
| `storage_devices` | `array[string]` | List of storage devices with name, model, size (from `lsblk` on Linux, `wmic` on Windows) |
| `partitions` | `array[object]` | List of mounted partitions with usage details |
| `gpus` | `array[string]` | List of GPU names (NVIDIA only via `nvidia-smi`); empty if none detected |

### Partition Object

| Field | Type | Description |
|-------|------|-------------|
| `device` | `string` | Device path (e.g., `/dev/nvme0n1p1`) |
| `mountpoint` | `string` | Mount point path (e.g., `/`, `/home`) |
| `fstype` | `string` | Filesystem type (e.g., `ext4`, `ntfs`) |
| `opts` | `string` | Mount options |
| `total_bytes` | `integer` | Total partition size in bytes |
| `used_bytes` | `integer` | Used space in bytes |
| `free_bytes` | `integer` | Free space in bytes |
| `percent_used` | `float` | Usage percentage |

### Example

```json
{
  "storage_devices": [
    "nvme0n1  Samsung SSD 980 PRO 1TB  1000.2G",
    "sda      WDC WD10EZEX-00W         1000.2G"
  ],
  "partitions": [
    {
      "device": "/dev/nvme0n1p2",
      "mountpoint": "/",
      "fstype": "ext4",
      "opts": "rw,relatime",
      "total_bytes": 500107862016,
      "used_bytes": 125829120000,
      "free_bytes": 348827648000,
      "percent_used": 26.5
    },
    {
      "device": "/dev/nvme0n1p1",
      "mountpoint": "/boot/efi",
      "fstype": "vfat",
      "opts": "rw,relatime",
      "total_bytes": 536870912,
      "used_bytes": 6291456,
      "free_bytes": 530579456,
      "percent_used": 1.2
    }
  ],
  "gpus": [
    "NVIDIA GeForce RTX 3080"
  ]
}
```

---

## network_info.json

Network interface information.

| Field | Type | Description |
|-------|------|-------------|
| `interfaces` | `object` | Map of interface name to interface details |
| `hostname` | `string` | System hostname |

### Interface Object

| Field | Type | Description |
|-------|------|-------------|
| `addresses` | `array[object]` | List of addresses assigned to interface |
| `is_up` | `boolean` | Whether interface is up |
| `speed_mbps` | `integer` | Link speed in Mbps; `null` if unavailable |
| `mtu` | `integer` | Maximum transmission unit |

### Address Object

| Field | Type | Description |
|-------|------|-------------|
| `family` | `string` | Address family (e.g., `AF_INET`, `AF_INET6`, `AF_PACKET`) |
| `address` | `string` | IP or MAC address |
| `netmask` | `string` | Network mask; `null` for some address types |
| `broadcast` | `string` | Broadcast address; `null` for some address types |

### Example

```json
{
  "interfaces": {
    "lo": {
      "addresses": [
        {
          "family": "AF_INET",
          "address": "127.0.0.1",
          "netmask": "255.0.0.0",
          "broadcast": null
        },
        {
          "family": "AF_INET6",
          "address": "::1",
          "netmask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
          "broadcast": null
        }
      ],
      "is_up": true,
      "speed_mbps": 0,
      "mtu": 65536
    },
    "eth0": {
      "addresses": [
        {
          "family": "AF_INET",
          "address": "192.168.1.100",
          "netmask": "255.255.255.0",
          "broadcast": "192.168.1.255"
        },
        {
          "family": "AF_PACKET",
          "address": "00:1a:2b:3c:4d:5e",
          "netmask": null,
          "broadcast": "ff:ff:ff:ff:ff:ff"
        }
      ],
      "is_up": true,
      "speed_mbps": 1000,
      "mtu": 1500
    }
  },
  "hostname": "workstation"
}
```

---

## os_info.json

Operating system information.

| Field | Type | Description |
|-------|------|-------------|
| `system` | `string` | Operating system name (e.g., `Linux`, `Windows`) |
| `release` | `string` | Kernel/OS release version (e.g., `6.5.0-44-generic`) |
| `version` | `string` | Full OS version string |
| `machine` | `string` | Machine hardware architecture (e.g., `x86_64`, `aarch64`) |
| `hostname` | `string` | System hostname |
| `country` | `string` | Two-letter country code from IP geolocation; `Unknown` if detection fails |
| `distribution` | `object` | Linux distribution details (Linux only) |

### Distribution Object (Linux only)

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Distribution name (e.g., `Ubuntu`, `Fedora`) |
| `version` | `string` | Distribution version (e.g., `22.04`) |
| `codename` | `string` | Distribution codename (e.g., `jammy`) |

### Example

```json
{
  "system": "Linux",
  "release": "6.5.0-44-generic",
  "version": "#44-Ubuntu SMP PREEMPT_DYNAMIC Fri Jun  7 15:10:09 UTC 2024",
  "machine": "x86_64",
  "hostname": "workstation",
  "country": "US",
  "distribution": {
    "name": "Ubuntu",
    "version": "22.04",
    "codename": "jammy"
  }
}
```
