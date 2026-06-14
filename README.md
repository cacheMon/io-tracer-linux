# IO-Tracer

## How it works
Visit [IO Tracer documentations](https://cachemon.github.io/iotracerdocs/) for more detail.

## Installation

### One-line installation
```bash
curl -sSL https://raw.githubusercontent.com/cacheMon/io-tracer/refs/heads/main/install.sh | sudo bash
```

### Manual Installation


1. Clone the repo

```bash
git clone https://github.com/cacheMon/io-tracer.git
cd io-tracer
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

3. Finally, install the remaining Python libraries!

```bash
# Ubuntu 
sudo apt install python3-psutil
sudo apt install python3-requests
sudo apt install python3-pytest
sudo apt install python3-zstandard


# ... (adjust the package manager for other distros)
```

`zstandard` is used to compress trace logs (`.zst`). If it is missing the
tracer still runs and keeps traces uncompressed, but installing it is
recommended. You can also install all Python dependencies at once with:

```bash
pip install -r requirements.txt
```

## Usage
```
usage: sudo iotrc [-h] [-v] [-a] [--computer-id] [--reward] [--no-upload] {dev} ...

Trace IO syscalls

options:
  -h, --help       show this help message and exit
  -v, --verbose    Print verbose output
  -a, --anonimize  Enable anonymization of process and file names
  --computer-id    Print this machine ID and exit
  --reward         Show your reward code (unlocked after uploading traces)
  --no-upload      Disable automatic upload of traces (for testing)

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
