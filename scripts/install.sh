#!/bin/bash

# GoGuard Installation Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BINARY_NAME="goguard"
SERVICE_NAME="goguard"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/goguard"
STATE_DIR="/var/lib/goguard"
LOG_DIR="/var/log/goguard"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_REPO="Charlie-Root/goguard"
VERSION="v1.0.0"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check for systemd
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
    
    # Check for firewall tools
    local firewall_found=false
    for fw in iptables ufw nft; do
        if command -v $fw &> /dev/null; then
            log_info "Found firewall tool: $fw"
            firewall_found=true
        fi
    done
    
    if ! $firewall_found; then
        log_warning "No firewall tools found. GoGuard will run in mock mode."
    fi
}

detect_architecture() {
    log_info "Detecting system architecture..."
    
    local arch=$(uname -m)
    local os="linux"
    
    case $arch in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    BINARY_FILE="goguard-${os}-${ARCH}"
    ARCHIVE_FILE="${BINARY_FILE}.tar.gz"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${ARCHIVE_FILE}"
    
    log_info "Detected: $os $ARCH"
    log_info "Will download: $ARCHIVE_FILE"
}

download_binary() {
    log_info "Downloading GoGuard binary..."
    
    # Create temporary directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download and extract
    if command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$ARCHIVE_FILE"
    elif command -v curl &> /dev/null; then
        curl -sL "$DOWNLOAD_URL" -o "$ARCHIVE_FILE"
    else
        log_error "Neither wget nor curl found. Please install one of them."
        exit 1
    fi
    
    if [[ ! -f "$ARCHIVE_FILE" ]]; then
        log_error "Failed to download $ARCHIVE_FILE"
        exit 1
    fi
    
    # Extract archive
    tar -xzf "$ARCHIVE_FILE"
    
    # Find the binary
    if [[ -f "$BINARY_FILE" ]]; then
        BINARY_PATH="$temp_dir/$BINARY_FILE"
    elif [[ -f "goguard" ]]; then
        BINARY_PATH="$temp_dir/goguard"
    else
        log_error "Binary not found in downloaded archive"
        exit 1
    fi
    
    # Test binary
    if ! "$BINARY_PATH" -version &>/dev/null; then
        log_warning "Binary version check failed, but continuing..."
    fi
    
    log_success "Binary downloaded successfully"
}

install_binary() {
    log_info "Installing GoGuard binary..."
    
    # Check if binary path is provided as argument
    if [[ -n "$1" && "$1" != "--download" ]]; then
        local binary_path="$1"
        if [[ ! -f "$binary_path" ]]; then
            log_error "Specified binary not found: $binary_path"
            exit 1
        fi
        BINARY_PATH="$binary_path"
    elif [[ "$1" == "--download" || -z "$1" ]]; then
        # Auto-download mode
        detect_architecture
        download_binary
    else
        # Find the binary in current directory
        local binary_path=""
        if [[ -f "./${BINARY_NAME}" ]]; then
            binary_path="./${BINARY_NAME}"
        elif [[ -f "./goguard-linux-amd64" ]]; then
            binary_path="./goguard-linux-amd64"
        elif [[ -f "./goguard-linux-arm64" ]]; then
            binary_path="./goguard-linux-arm64"
        else
            log_error "GoGuard binary not found in current directory"
            log_info "Available options:"
            log_info "  1. Auto-download: $0 --download"
            log_info "  2. Build from source: go build -o goguard ."
            log_info "  3. Specify binary path: $0 /path/to/goguard-binary"
            exit 1
        fi
        BINARY_PATH="$binary_path"
    fi
    
    # Install binary
    cp "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    
    log_success "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

create_directories() {
    log_info "Creating directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR"
    mkdir -p "$LOG_DIR"
    
    # Set ownership and permissions
    chown root:root "$CONFIG_DIR"
    chown root:root "$STATE_DIR"
    chown root:root "$LOG_DIR"
    
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$STATE_DIR"
    chmod 755 "$LOG_DIR"
    
    log_success "Directories created"
}

download_config() {
    log_info "Creating default configuration..."
    
    local temp_config="/tmp/goguard-config.yaml"
    
    # Create a basic production config instead of downloading
    cat > "$temp_config" << 'EOF'
log_files:
- path: /var/log/nginx/access.log
  patterns:
  - ban_time: 2h
    ip_group: 1
    regex: (\d+\.\d+\.\d+\.\d+) .* "[^"]*" 404
    threshold: 5

- path: /var/log/auth.log
  patterns:
  - ban_time: 1h
    ip_group: 1
    regex: Failed password for .* from (\d+\.\d+\.\d+\.\d+) port \d+( ssh2)?
    threshold: 3
  - ban_time: 1h
    ip_group: 1
    regex: Invalid user .* from (\d+\.\d+\.\d+\.\d+) port \d+
    threshold: 3

production_mode: true
web:
  enabled: true
  port: 8080

abuse_reporting:
  enabled: false
  
firewall:
  type: auto

whitelist:
- 127.0.0.1
- ::1
- 192.168.0.0/16
- 10.0.0.0/8
- 172.16.0.0/12
EOF
    CONFIG_SOURCE="$temp_config"
    log_success "Default configuration created"
}

install_config() {
    log_info "Installing configuration..."
    
    # Check for local config first - look in current directory where script is run from
    local current_dir=$(pwd)
    if [[ -f "${current_dir}/config.yaml" ]]; then
        CONFIG_SOURCE="${current_dir}/config.yaml"
        log_info "Using local configuration file: ${current_dir}/config.yaml"
    elif [[ -f "config.yaml" ]]; then
        CONFIG_SOURCE="config.yaml"
        log_info "Using local configuration file"
    else
        download_config
    fi
    
    if [[ -f "${CONFIG_DIR}/config.yaml" ]]; then
        log_warning "Configuration already exists, backing up..."
        cp "${CONFIG_DIR}/config.yaml" "${CONFIG_DIR}/config.yaml.backup.$(date +%Y%m%d-%H%M%S)"
    fi
    
    cp "$CONFIG_SOURCE" "${CONFIG_DIR}/config.yaml"
    chmod 644 "${CONFIG_DIR}/config.yaml"
    log_success "Configuration installed to ${CONFIG_DIR}/config.yaml"
}

install_service() {
    log_info "Installing systemd service..."
    
    if [[ -f "scripts/goguard.service" ]]; then
        cp "scripts/goguard.service" "$SERVICE_FILE"
    else
        # Create service file inline if not found
        cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=GoGuard - Advanced Intrusion Detection & Response System
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/goguard -config /etc/goguard/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
TimeoutStopSec=30
WorkingDirectory=/var/lib/goguard
Environment=GOGUARD_CONFIG=/etc/goguard/config.yaml

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
    
    log_success "Service file installed"
}

setup_logrotate() {
    log_info "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/${SERVICE_NAME}" << EOF
${LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload ${SERVICE_NAME} 2>/dev/null || true
    endscript
}
EOF
    
    log_success "Log rotation configured"
}

main() {
    log_info "Starting GoGuard installation..."
    
    check_root
    check_dependencies
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    install_binary "$1"
    create_directories
    install_config
    install_service
    setup_logrotate
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log_success "GoGuard installation completed!"
    echo
    log_info "Configuration has been optimized for production use."
    log_info "Next steps:"
    echo "  1. Review configuration: sudo nano ${CONFIG_DIR}/config.yaml"
    echo "  2. Add your log files and adjust whitelist as needed"
    echo "  3. Start the service: sudo systemctl start ${SERVICE_NAME}"
    echo "  4. Check status: sudo systemctl status ${SERVICE_NAME}"
    echo "  5. View logs: sudo journalctl -u ${SERVICE_NAME} -f"
    echo "  6. Access web interface: http://localhost:8080"
    echo
    log_warning "Make sure to whitelist your management IPs before starting!"
}

# Show usage if help requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 [options]"
    echo
    echo "Install GoGuard as a systemd service"
    echo
    echo "Options:"
    echo "  --download               Auto-download latest binary (default)"
    echo "  /path/to/binary         Use specific binary file"
    echo "  -h, --help              Show this help"
    echo
    echo "Examples:"
    echo "  $0                      # Auto-download and install"
    echo "  $0 --download           # Explicitly auto-download"
    echo "  $0 ./goguard           # Use local binary"
    echo
    echo "Note: Run as root (sudo)"
    exit 0
fi

main "$@"
