#!/bin/bash

# GoGuard Uninstallation Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="goguard"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/goguard"
STATE_DIR="/var/lib/goguard"
LOG_DIR="/var/log/goguard"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        exit 1
    fi
}

main() {
    check_root
    
    log_info "Uninstalling GoGuard..."
    
    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        log_info "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [[ -f "$SERVICE_FILE" ]]; then
        rm "$SERVICE_FILE"
        systemctl daemon-reload
        log_success "Service removed"
    fi
    
    # Remove binary
    if [[ -f "${INSTALL_DIR}/goguard" ]]; then
        rm "${INSTALL_DIR}/goguard"
        log_success "Binary removed"
    fi
    
    # Remove logrotate config
    if [[ -f "/etc/logrotate.d/${SERVICE_NAME}" ]]; then
        rm "/etc/logrotate.d/${SERVICE_NAME}"
        log_success "Log rotation config removed"
    fi
    
    # Ask about data removal
    echo
    log_warning "The following directories contain configuration and data:"
    echo "  - Configuration: $CONFIG_DIR"
    echo "  - State data: $STATE_DIR"
    echo "  - Logs: $LOG_DIR"
    echo
    read -p "Remove all data? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
        log_success "All data removed"
    else
        log_info "Data preserved"
    fi
    
    log_success "GoGuard uninstalled successfully!"
}

main "$@"
