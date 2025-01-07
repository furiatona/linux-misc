#!/bin/bash

# Author: Dheny @furiatona on GitHub
# Bash script to check port status, configure firewall, or test network speed.
# Supports multiple Linux distros and installs missing dependencies if needed.

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Utility function for logging
log() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root for firewall configuration."
    exit 1
fi

# Check prerequisites
log "Checking required commands..."
MISSING_PKGS=()
for cmd in ss wget curl; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_PKGS+=("$cmd")
    fi
done

if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
    echo -e "${YELLOW}The following required packages are missing: ${MISSING_PKGS[*]}${RESET}"
    read -rp "Do you want to install them automatically? [Y/n] (default: Y): " install_choice
    install_choice=${install_choice:-Y}

    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        # Detect OS and install missing packages
        if [ -f /etc/os-release ]; then
            source /etc/os-release
            case "$ID" in
                almalinux|centos|rocky)
                    log "Installing packages on $PRETTY_NAME using yum/dnf..."
                    yum install -y epel-release
                    yum install -y iproute wget curl || { error "Failed to install packages."; exit 1; }
                    ;;
                debian|ubuntu)
                    log "Installing packages on $PRETTY_NAME using apt..."
                    apt update -y && apt install -y iproute2 wget curl || { error "Failed to install packages."; exit 1; }
                    ;;
                fedora)
                    log "Installing packages on $PRETTY_NAME using dnf..."
                    dnf install -y iproute wget curl || { error "Failed to install packages."; exit 1; }
                    ;;
                *)
                    error "Unsupported OS. Please install the required packages manually."
                    exit 1
                    ;;
            esac
        else
            error "Cannot detect OS version. Please install ss, wget, and curl manually."
            exit 1
        fi
        success "All required packages have been installed successfully."
    else
        error "Cannot continue without the required packages. Exiting."
        exit 1
    fi
else
    success "All prerequisites are met."
fi

# Display menu
echo -e "\n${CYAN}Select an option (default: 1):${RESET}"
echo -e "${YELLOW}Press [Enter] for option 1 by default.${RESET}"
echo "1) Check port open"
echo "2) Check slow network"
read -rp "Enter choice (1/2): " choice
choice=${choice:-1}

if [ "$choice" == "1" ]; then
    # --- Check port open ---
    while :; do
        echo -e "${YELLOW}Type 'exit' or press Ctrl+C to cancel the script.${RESET}"
        read -rp "Enter the port number (or type 'exit' to cancel): " port_number
        if [[ "$port_number" == "exit" ]]; then
            log "Script cancelled by the user."
            exit 0
        elif [[ "$port_number" =~ ^[0-9]+$ ]]; then
            break
        else
            error "Invalid input. Please enter a valid port number or type 'exit'."
        fi
    done

    log "Checking if port $port_number is listening..."
    if ! ss -tuln | grep -q ":$port_number "; then
        error "No application is running on port $port_number."
        exit 1
    else
        success "Port $port_number is open and listening."
    fi

    # Detect firewall type and status
    log "Detecting firewall..."
    if systemctl is-active --quiet firewalld; then
        firewall_type="firewalld"
        log "Firewall detected: firewalld is active."
        if firewall-cmd --list-ports | grep -q "${port_number}/tcp"; then
            log "Port $port_number is already allowed in firewalld."
        else
            log "Allowing port $port_number in firewalld..."
            firewall-cmd --permanent --add-port="${port_number}/tcp"
            firewall-cmd --reload
            success "Port $port_number allowed successfully in firewalld."
        fi
    elif ufw status | grep -q "Status: active"; then
        firewall_type="ufw"
        log "Firewall detected: UFW is active."
        if ufw status | grep -q "$port_number"; then
            log "Port $port_number is already allowed in UFW."
        else
            log "Allowing port $port_number in UFW..."
            ufw allow "$port_number"
            ufw reload
            success "Port $port_number allowed successfully in UFW."
        fi
    elif iptables -L | grep -q "Chain"; then
        firewall_type="iptables"
        log "Firewall detected: iptables is active."
        if iptables -L INPUT -v -n | grep -q "$port_number"; then
            log "Port $port_number is already allowed in iptables."
        else
            log "Allowing port $port_number in iptables..."
            iptables -A INPUT -p tcp --dport "$port_number" -j ACCEPT
            iptables-save > /etc/iptables/rules.v4
            success "Port $port_number allowed successfully in iptables."
        fi
    elif nft list ruleset &>/dev/null; then
        firewall_type="nftables"
        log "Firewall detected: nftables is active."
        if nft list ruleset | grep -q "$port_number"; then
            log "Port $port_number is already allowed in nftables."
        else
            log "Allowing port $port_number in nftables..."
            nft add rule ip filter input tcp dport "$port_number" accept
            nft list ruleset > /etc/nftables.conf
            success "Port $port_number allowed successfully in nftables."
        fi
    else
        success "No active firewall detected. Port $port_number should be accessible."
    fi

elif [ "$choice" == "2" ]; then
    # --- Check slow network ---
    log "Checking network speed..."
    log "Downloading test file (100MB)..."
    download_speed=$(wget -O /dev/null http://test.b-cdn.net/100mb.bin 2>&1 | grep -oE '[0-9.]+ [KM]B/s' | tail -1)
    if [[ "$download_speed" =~ ([0-9.]+)\ ([KM])B/s ]]; then
        speed_value="${BASH_REMATCH[1]}"
        unit="${BASH_REMATCH[2]}"

        # Convert to MB if necessary
        if [[ "$unit" == "K" ]]; then
            speed_value=$(awk "BEGIN {print $speed_value / 1024}")
        fi

        if (( $(echo "$speed_value >= 30" | awk '{print ($1 >= 30)}') )); then
            success "Network speed test completed: ${speed_value} MB/s. It looks satisfactory."
        else
            error "Network speed test completed: ${speed_value} MB/s. Please contact support if the speed is insufficient."
        fi
    else
        error "Failed to determine network speed."
    fi
else
    error "Invalid choice. Exiting."
    exit 1
fi