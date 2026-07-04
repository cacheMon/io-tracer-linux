# IO-Tracer

## How it works
Visit [IO Tracer documentations](https://cachemon.github.io/iotracerdocs/) for more detail.

## Installation

### One-line installation
```bash
curl -fsSL https://raw.githubusercontent.com/cacheMon/io-tracer-linux/main/install.sh | sudo bash
```
The installer clones the repo, installs BCC + the Python dependencies, and sets
up the `iotrc` command. Re-run it any time to update to the latest version.

### Manual Installation


1. Clone the repo

```bash
git clone https://github.com/cacheMon/io-tracer-linux.git
cd io-tracer-linux
```

2. Install BCC

```bash
# Debian
echo deb [http://cloudfront.debian.net/debian](http://cloudfront.debian.net/debian) sid main >> /etc/apt/sources.list
sudo apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r)

# Ubuntu
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# Fedora
sudo dnf install bcc

# Arch
pacman -S bcc bcc-tools python-bcc
```

For more distros, visit the official [BCC's installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

3. Finally, install the Python dependencies. Prefer your distro's packages
(the tracer runs under the system Python, which is what the distro `bcc`
bindings are built for — see the next code block). If you use pip instead,
note that Debian 12 / Ubuntu 23.04+ mark the system interpreter as
externally managed (PEP 668), so a bare `pip install` fails; append
`--break-system-packages` or use the distro packages:

```bash
pip install -r requirements.txt
```

Distro package manager equivalents:

```bash
# Ubuntu / Debian
sudo apt install python3-psutil python3-requests python3-zstandard

# Fedora
sudo dnf install python3-psutil python3-requests python3-zstandard

# Arch
sudo pacman -S python-psutil python-requests python-zstandard
```

`zstandard` is used to compress trace logs (`.zst`). If it is missing the
tracer still runs and falls back to gzip (`.gz`) using the Python standard
library, but installing `zstandard` is recommended for faster, smaller output.
To run the test suite you'll also need `pytest` (`pip install pytest`).

## Usage
```
usage: sudo iotrc [-h] [-v] [-a] [--cache] [--network] [--computer-id] [--reward] [--no-upload] [--output DIR] {dev} ...

Trace IO syscalls

options:
  -h, --help       show this help message and exit
  -v, --verbose    Print verbose output
  -a, --anonimize  Enable anonymization of process and file names
  --computer-id    Print this machine ID and exit
  --reward         Show your reward code (unlocked after uploading traces)
  --no-upload      Disable automatic upload of traces (for testing)
  --output DIR     Base directory for trace output (default: system temp dir)

subcommands:
  {dev}            Run in developer mode with extra logs and checks
                   (supports --trace-bucket NAME to override the upload bucket)
```

## Trace Types

Internal documentation on trace types and collection methods is available in [docs/TRACE_TYPES.md](docs/TRACE_TYPES.md).

## Use as a service
We provided a simple bash script that installs and enable IO Traces as a service. Feel free to tinker with it and suit it to your best needs!

```
Usage: sudo bash ./scripts/install_service.sh {install|uninstall|status|start|stop|restart|logs}

Options:
  install      Install and enable the service
  uninstall    Stop and remove the service
  status       Show service status
  start        Start the service now
  stop         Stop the service
  restart      Restart the service
  logs         View live service logs
```

## Uninstall

Run the uninstaller from your local repo:

```bash
sudo bash ~/io-tracer/uninstall.sh
```

This will:
- Remove the `iotrc` binary from `/usr/local/bin`
- Optionally delete the cloned repo at `~/io-tracer` (you'll be prompted)
