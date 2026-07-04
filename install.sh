#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    REAL_USER="$USER"
    REAL_HOME="$HOME"
fi

INSTALL_DIR="$REAL_HOME/io-tracer"
REPO_URL="https://github.com/cacheMon/io-tracer-linux.git"
RAW_URL="https://raw.githubusercontent.com/cacheMon/io-tracer-linux/main/iotrc.py"
BIN_NAME="iotrc"
BIN_DIR="/usr/local/bin"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                    IO-Tracer Installer                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "python3 is not installed. Please install Python 3.7+ and re-run."
        exit 1
    fi

    # The tracer uses time.time_ns / subprocess(text=...) (3.7+). Annotations
    # are PEP 563-lazy, so 3.7-3.9 work; RHEL 8's stock 3.6 does NOT — use the
    # python38+ AppStream there (with the matching python3X-bcc bindings).
    PY_VERSION=$(python3 -c 'import sys; print("%d%02d" % sys.version_info[:2])')
    if [ "$PY_VERSION" -lt 307 ]; then
        PY_LABEL=$(python3 --version 2>&1)
        log_error "Python 3.7+ is required (found $PY_LABEL)"
        exit 1
    fi

    log_success "Python $(python3 --version 2>&1 | awk '{print $2}') detected"
}

# Kernel headers are needed by BCC to compile the eBPF program at runtime,
# but the exact linux-headers-$(uname -r) package is often unavailable (WSL2
# kernels, cloud images whose running kernel left the mirrors). Never let a
# missing headers package abort the whole install: BCC can also compile from
# the kernel's embedded headers (CONFIG_IKHEADERS, /sys/kernel/kheaders.tar.xz).
install_kernel_headers_apt() {
    apt-get install -y "linux-headers-$(uname -r)" || {
        log_warning "linux-headers-$(uname -r) is not available from apt (normal on WSL2 and stale cloud images)."
        if [ -d "/lib/modules/$(uname -r)/build" ] || [ -e /sys/kernel/kheaders.tar.xz ]; then
            log_info "Kernel headers are available another way (build dir or CONFIG_IKHEADERS); continuing."
        else
            log_warning "No kernel headers found: the tracer will fail to compile until headers are provided."
            log_warning "On WSL2, build headers from https://github.com/microsoft/WSL2-Linux-Kernel or enable CONFIG_IKHEADERS."
        fi
    }
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_LIKE=$ID_LIKE
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/fedora-release ]; then
        DISTRO="fedora"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
    
    DISTRO=$(echo "$DISTRO" | tr '[:upper:]' '[:lower:]')
    
    log_info "Detected distribution: $DISTRO"
}

install_bcc_ubuntu() {
    log_info "Installing BCC for Ubuntu/Debian-based system..."
    apt-get update -qq
    # bcc itself is a hard requirement (fatal); headers are best-effort.
    apt-get install -y bpfcc-tools
    install_kernel_headers_apt
}

install_bcc_debian() {
    log_info "Installing BCC for Debian..."
    # bpfcc-tools/libbpfcc have shipped in Debian stable main since buster —
    # no sid repository needed. (An earlier version of this script appended
    # the sid repo to /etc/apt/sources.list, which risks partial upgrades to
    # unstable on any later `apt upgrade`. If a previous run added it, remove
    # the "deb http://cloudfront.debian.net/debian sid main" line.)
    apt-get update -qq
    apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev
    install_kernel_headers_apt
}

install_bcc_fedora() {
    log_info "Installing BCC for Fedora/RHEL-family..."
    dnf install -y bcc bcc-tools python3-bcc
    # Match the running kernel where possible; plain kernel-devel as fallback
    # (also covers install_weak_deps=False setups where the bcc RPM's
    # "Recommends: kernel-devel" is not honored).
    dnf install -y "kernel-devel-$(uname -r)" || dnf install -y kernel-devel || \
        log_warning "kernel-devel unavailable; BCC will rely on embedded headers (CONFIG_IKHEADERS) if present"
}

install_bcc_amazon() {
    # Amazon Linux 2023 ships dnf + bcc in the base repos; Amazon Linux 2
    # (EOL 2026-06-30) needs amazon-linux-extras and is not supported —
    # rejected outright, even if dnf happens to be installed on it (its
    # repos still lack bcc, so the install would fail mid-flight anyway).
    if [ "${VERSION_ID%%.*}" = "2" ]; then
        log_error "Amazon Linux 2 is past end-of-life and not supported; use Amazon Linux 2023."
        exit 1
    fi
    log_info "Installing BCC for Amazon Linux 2023..."
    dnf install -y bcc bcc-tools python3-bcc
    dnf install -y "kernel-devel-$(uname -r)" || dnf install -y kernel-devel || \
        log_warning "kernel-devel unavailable; BCC will rely on embedded headers (CONFIG_IKHEADERS) if present"
}

install_bcc_arch() {
    log_info "Installing BCC for Arch Linux..."
    pacman -Sy --noconfirm bcc bcc-tools python-bcc
}

install_python_deps_apt() {
    log_info "Installing Python dependencies..."
    apt-get install -y python3-psutil python3-requests
    # zstandard is optional: the tracer falls back to gzip (.gz) compression when
    # it is missing, so don't let an unavailable package abort the install.
    apt-get install -y python3-zstandard || log_warning "python3-zstandard unavailable; traces will be compressed with gzip (.gz) instead"
}

install_python_deps_dnf() {
    log_info "Installing Python dependencies..."
    dnf install -y python3-psutil python3-requests
    # Optional; see install_python_deps_apt.
    dnf install -y python3-zstandard || log_warning "python3-zstandard unavailable; traces will be compressed with gzip (.gz) instead"
}

install_python_deps_pacman() {
    log_info "Installing Python dependencies..."
    pacman -S --noconfirm python-psutil python-requests
    # Optional; see install_python_deps_apt.
    pacman -S --noconfirm python-zstandard || log_warning "python-zstandard unavailable; traces will be compressed with gzip (.gz) instead"
}

install_git_if_needed() {
    if ! command -v git &> /dev/null; then
        log_info "Installing git..."
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                apt-get install -y git
                ;;
            fedora|rhel|centos|rocky|almalinux|amzn)
                dnf install -y git
                ;;
            arch|manjaro)
                pacman -S --noconfirm git
                ;;
        esac
    fi
}

clone_repo() {
    if [ -d "$INSTALL_DIR" ]; then
        log_warning "IO-Tracer already exists at $INSTALL_DIR"
        log_info "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull origin main || git pull origin master
    else
        log_info "Cloning IO-Tracer to $INSTALL_DIR..."
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

install_bin() {
    log_info "Installing $BIN_NAME wrapper to $BIN_DIR..."

    # The wrapper execs iotrc.py by absolute path from whatever directory the
    # user is in: imports resolve via sys.path[0] (the script's directory) and
    # iotrc.py resolves the BPF source relative to __file__, so no cd is
    # needed. (An earlier comment here claimed the CWD had to be the repo
    # root — that was never enforced and is not required.)
    cat > "$BIN_DIR/$BIN_NAME" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/iotrc.py" "\$@"
EOF

    chmod +x "$BIN_DIR/$BIN_NAME"
    log_success "Installed wrapper: $BIN_DIR/$BIN_NAME -> $INSTALL_DIR/iotrc.py"
}

install_dependencies() {
    case "$DISTRO" in
        ubuntu|linuxmint|pop)
            install_bcc_ubuntu
            install_python_deps_apt
            ;;
        debian)
            install_bcc_debian
            install_python_deps_apt
            ;;
        fedora)
            install_bcc_fedora
            install_python_deps_dnf
            ;;
        rhel|centos|rocky|almalinux)
            log_warning "RHEL-based distro detected. Using dnf..."
            install_bcc_fedora
            install_python_deps_dnf
            ;;
        amzn)
            install_bcc_amazon
            install_python_deps_dnf
            ;;
        arch|manjaro)
            install_bcc_arch
            install_python_deps_pacman
            ;;
        *)
            # Try to detect based on ID_LIKE
            if [[ "$DISTRO_LIKE" == *"debian"* ]] || [[ "$DISTRO_LIKE" == *"ubuntu"* ]]; then
                install_bcc_ubuntu
                install_python_deps_apt
            elif [[ "$DISTRO_LIKE" == *"fedora"* ]] || [[ "$DISTRO_LIKE" == *"rhel"* ]]; then
                install_bcc_fedora
                install_python_deps_dnf
            elif [[ "$DISTRO_LIKE" == *"arch"* ]]; then
                install_bcc_arch
                install_python_deps_pacman
            else
                log_error "Unsupported distribution: $DISTRO"
                log_error "Please install BCC manually: https://github.com/iovisor/bcc/blob/master/INSTALL.md"
                exit 1
            fi
            ;;
    esac
}

print_success() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           IO-Tracer Installed Successfully!              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Installation directory: $INSTALL_DIR"
    echo "Binary:                 $BIN_DIR/$BIN_NAME"
    echo ""
    echo "To run IO-Tracer:"
    echo "  sudo $BIN_NAME"
    echo ""
    echo "To install as a systemd service:"
    echo "  sudo bash $INSTALL_DIR/scripts/install_service.sh install"
    echo ""
    echo "For more options, run:"
    echo "  sudo $BIN_NAME --help"
    echo ""
    echo "To uninstall:"
    echo "  sudo bash $INSTALL_DIR/uninstall.sh"
    echo ""
}

main() {
    print_banner
    check_root
    check_python
    detect_distro
    
    log_info "Starting IO-Tracer installation..."
    echo ""
    
    install_git_if_needed
    install_dependencies
    log_success "Dependencies installed"
    
    clone_repo
    log_success "Repository cloned"

    install_bin
    
    print_success
}

main "$@"
