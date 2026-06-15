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
REPO_URL="https://github.com/cacheMon/io-tracer.git"
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
        log_error "python3 is not installed. Please install Python 3.6+ and re-run."
        exit 1
    fi

    PY_VERSION=$(python3 -c 'import sys; print("%d%02d" % sys.version_info[:2])')
    if [ "$PY_VERSION" -lt 306 ]; then
        PY_LABEL=$(python3 --version 2>&1)
        log_error "Python 3.6+ is required (found $PY_LABEL)"
        exit 1
    fi

    log_success "Python $(python3 --version 2>&1 | awk '{print $2}') detected"
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
    apt-get install -y bpfcc-tools linux-headers-$(uname -r)
}

install_bcc_debian() {
    log_info "Installing BCC for Debian..."
    
    # Check if sid repo is already added
    if ! grep -q "debian sid main" /etc/apt/sources.list 2>/dev/null; then
        log_info "Adding Debian sid repository for BCC..."
        echo "deb http://cloudfront.debian.net/debian sid main" >> /etc/apt/sources.list
    fi
    
    apt-get update -qq
    apt-get install -y bpfcc-tools libbpfcc libbpfcc-dev linux-headers-$(uname -r)
}

install_bcc_fedora() {
    log_info "Installing BCC for Fedora..."
    dnf install -y bcc bcc-tools python3-bcc
}

install_bcc_arch() {
    log_info "Installing BCC for Arch Linux..."
    pacman -Sy --noconfirm bcc bcc-tools python-bcc
}

install_python_deps_apt() {
    log_info "Installing Python dependencies..."
    apt-get install -y python3-psutil python3-requests
    # zstandard is optional: the tracer falls back to uncompressed traces when
    # it is missing, so don't let an unavailable package abort the install.
    apt-get install -y python3-zstandard || log_warning "python3-zstandard unavailable; traces will not be compressed"
}

install_python_deps_dnf() {
    log_info "Installing Python dependencies..."
    dnf install -y python3-psutil python3-requests
    # Optional; see install_python_deps_apt.
    dnf install -y python3-zstandard || log_warning "python3-zstandard unavailable; traces will not be compressed"
}

install_python_deps_pacman() {
    log_info "Installing Python dependencies..."
    pacman -S --noconfirm python-psutil python-requests
    # Optional; see install_python_deps_apt.
    pacman -S --noconfirm python-zstandard || log_warning "python-zstandard unavailable; traces will not be compressed"
}

install_git_if_needed() {
    if ! command -v git &> /dev/null; then
        log_info "Installing git..."
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                apt-get install -y git
                ;;
            fedora|rhel|centos)
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

    # Write a wrapper script so that iotrc.py is always executed from inside
    # the repo directory. This is required because iotrc.py uses package-relative
    # imports (from src.tracer.IOTracer import ...) which only resolve when
    # Python's working directory is the repo root.
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
            dnf install -y bcc bcc-tools python3-bcc
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
