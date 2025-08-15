#!/bin/bash

# Script Name: ITAM Server Readiness Checker
# Author: furiatona
# Version: 2.1
# Date: August 15, 2025
# Description: Periodic server readiness checks with documentation links for warnings.
# Usage: Run as root: sudo ./itam-reqs.sh

# Exit on unset variables, pipe failures
set -uo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Check results storage
declare -A CHECK_RESULTS
declare -A CHECK_MESSAGES
declare -A DOC_LINKS  # Store documentation links for warnings
declare -a CHECK_ORDER=("OS" "CPU" "MEMORY" "DISK" "DOCKER" "COMPOSE" "INTERNET" "PUBLIC_IP" "FIREWALL" "SECURITY" "UPDATES" "SSH" "TIME" "BACKUP" "CERTBOT")

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    case "$level" in
        INFO) echo -e "${timestamp} [${BLUE}INFO${NC}] ${message}" ;;
        WARN) echo -e "${timestamp} [${YELLOW}WARN${NC}] ${message}" ;;
        ERROR) echo -e "${timestamp} [${RED}ERROR${NC}] ${message}" ;;
        SUCCESS) echo -e "${timestamp} [${GREEN}SUCCESS${NC}] ${message}" ;;
        DOC) echo -e "${timestamp} [${PURPLE}DOC${NC}] ${message}" ;;
        *) echo -e "${timestamp} [INFO] ${message}" ;;
    esac
}

# Add documentation link for a check
add_doc_link() {
    local check_id="$1"
    local link="$2"
    DOC_LINKS["$check_id"]="$link"
}

# Record check outcome
record_check() {
    local id="$1"
    local status="$2"   # PASS, WARN, FAIL, SKIP
    local message="$3"
    CHECK_RESULTS["$id"]="$status"
    CHECK_MESSAGES["$id"]="$message"
}

# Check internet connectivity
check_internet() {
    local check_id="INTERNET"
    if command_exists curl; then
        if curl -Is --connect-timeout 5 https://google.com >/dev/null 2>&1; then
            record_check "$check_id" "PASS" "Internet connectivity confirmed"
            log SUCCESS "Internet connectivity confirmed"
            return 0
        fi
    fi
    record_check "$check_id" "WARN" "No internet connection detected"
    log WARN "No internet connection detected"
    add_doc_link "$check_id" "https://ubuntu.com/server/docs/network-connectivity"
    return 1
}

# Main check function
perform_checks() {
    log INFO "Starting ITAM Server Readiness Checks..."
    
    # Reset documentation links
    unset DOC_LINKS
    declare -gA DOC_LINKS

    # Check 1: OS Compatibility
    local check_id="OS"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" =~ ^(debian|ubuntu)$ ]]; then
            record_check "$check_id" "PASS" "OS: $PRETTY_NAME (compatible)"
            log SUCCESS "OS is $PRETTY_NAME, which is compatible."
        else
            record_check "$check_id" "FAIL" "OS: $PRETTY_NAME (incompatible)"
            log ERROR "OS is $PRETTY_NAME, which is not Debian or Ubuntu-based."
            add_doc_link "$check_id" "https://ubuntu.com/download/server"
        fi
    else
        record_check "$check_id" "FAIL" "Unable to determine OS"
        log ERROR "Unable to determine OS. /etc/os-release not found."
        add_doc_link "$check_id" "https://ubuntu.com/download/server"
    fi

    # Check 2: CPU Cores
    check_id="CPU"
    cpu_cores=$(nproc --all 2>/dev/null || echo 0)
    if [ "$cpu_cores" -ge 4 ]; then
        record_check "$check_id" "PASS" "CPU cores: $cpu_cores (>=4 required)"
        log SUCCESS "CPU cores: $cpu_cores (meets minimum of 4)."
    else
        record_check "$check_id" "FAIL" "Insufficient CPU cores: $cpu_cores (need 4+)"
        log WARN "Insufficient CPU cores: Detected $cpu_cores (minimum required: 4)."
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/architecture"
    fi

    # Check 3: Memory
    check_id="MEMORY"
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}' 2>/dev/null || echo 0)
    total_mem_gb=$((total_mem_kb / 1024 / 1024))
    if [ "$total_mem_gb" -ge 6 ]; then
        record_check "$check_id" "PASS" "Memory: ${total_mem_gb}GB (>=6GB required)"
        log SUCCESS "Memory: ${total_mem_gb}GB (meets minimum of 6GB)."
    else
        record_check "$check_id" "FAIL" "Insufficient memory: ${total_mem_gb}GB (need 6GB+)"
        log WARN "Insufficient memory: Detected ${total_mem_gb}GB (minimum required: 6GB)."
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/architecture"
    fi

    # Check 4: Disk Space
    check_id="DISK"
    free_space_kb=$(df -k / | awk 'NR==2 {print $4}' 2>/dev/null || echo 0)
    free_space_gb=$((free_space_kb / 1024 / 1024))
    if [ "$free_space_gb" -ge 20 ]; then
        record_check "$check_id" "PASS" "Disk space: ${free_space_gb}GB (>=20GB required)"
        log SUCCESS "Free disk space on root: ${free_space_gb}GB (meets minimum of 20GB)."
    else
        record_check "$check_id" "WARN" "Low disk space: ${free_space_gb}GB (recommend 20GB+)"
        log WARN "Insufficient free disk space on root: ${free_space_gb}GB (recommended minimum: 20GB)."
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/storage-expansion"
    fi

    # Check 5: Docker
    check_id="DOCKER"
    if command_exists docker; then
        docker_version=$(docker --version | awk '{print $3}' | sed 's/,//')
        record_check "$check_id" "PASS" "Docker installed (v$docker_version)"
        log SUCCESS "Docker is installed (version: $docker_version)."
    else
        record_check "$check_id" "FAIL" "Docker not installed"
        log WARN "Docker is not installed."
        add_doc_link "$check_id" "https://docs.docker.com/engine/install/ubuntu/"
    fi

    # Check 6: Docker Compose
    check_id="COMPOSE"
    if command_exists docker-compose; then
        compose_version=$(docker-compose --version | awk '{print $3}' | sed 's/,//')
        record_check "$check_id" "PASS" "Docker Compose installed (v$compose_version)"
        log SUCCESS "Docker Compose is installed (version: $compose_version)."
    elif command_exists docker && docker compose version >/dev/null 2>&1; then
        compose_version=$(docker compose version | awk '{print $4}')
        record_check "$check_id" "PASS" "Docker Compose plugin installed (v$compose_version)"
        log SUCCESS "Docker Compose plugin is installed (version: $compose_version)."
    else
        record_check "$check_id" "WARN" "Docker Compose not installed"
        log WARN "Docker Compose is not installed."
        add_doc_link "$check_id" "https://docs.docker.com/compose/install/"
    fi

    # Check 7: Internet Connectivity
    check_internet

    # Check 8: Public IP
    check_id="PUBLIC_IP"
    if [ "${CHECK_RESULTS[INTERNET]}" == "PASS" ]; then
        external_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")
        if [ "$external_ip" != "unknown" ] && [ "$external_ip" != "" ]; then
            local_ips=$(ip addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' || echo "")
            if echo "$local_ips" | grep -q "$external_ip"; then
                record_check "$check_id" "PASS" "Public IP: $external_ip"
                log SUCCESS "Server has a public IP: $external_ip."
            else
                record_check "$check_id" "WARN" "Behind NAT (External: $external_ip)"
                log WARN "Server does not have a public IP (behind NAT or proxy). External IP: $external_ip."
                add_doc_link "$check_id" "https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/"
            fi
        else
            record_check "$check_id" "WARN" "Unable to detect public IP"
            log WARN "Unable to detect public IP address."
        fi
    else
        record_check "$check_id" "SKIP" "Skipped (no internet)"
        log INFO "Skipping public IP check due to internet unavailability"
    fi

    # Check 9: Firewall
    check_id="FIREWALL"
    if command_exists ufw; then
        if ufw status | grep -q "Status: active"; then
            record_check "$check_id" "PASS" "UFW firewall active"
            log SUCCESS "UFW firewall is active."
        else
            record_check "$check_id" "WARN" "UFW firewall inactive"
            log WARN "UFW firewall is inactive."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/security-firewall"
        fi
    elif command_exists firewall-cmd; then
        if firewall-cmd --state | grep -q "running"; then
            record_check "$check_id" "PASS" "Firewalld active"
            log SUCCESS "Firewalld is active."
        else
            record_check "$check_id" "WARN" "Firewalld inactive"
            log WARN "Firewalld is inactive."
            add_doc_link "$check_id" "https://firewalld.org/documentation/"
        fi
    else
        record_check "$check_id" "WARN" "No firewall detected"
        log WARN "No common firewall (UFW or firewalld) detected."
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/security-firewall"
    fi

    # Check 10: AppArmor/SELinux
    check_id="SECURITY"
    if command_exists aa-status; then
        if aa-status | grep -q "apparmor module is loaded"; then
            record_check "$check_id" "PASS" "AppArmor enabled"
            log SUCCESS "AppArmor is enabled."
        else
            record_check "$check_id" "WARN" "AppArmor not enabled"
            log WARN "AppArmor is not enabled."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/security-apparmor"
        fi
    elif command_exists sestatus; then
        if sestatus | grep -q "SELinux status:.*enabled"; then
            record_check "$check_id" "PASS" "SELinux enabled"
            log SUCCESS "SELinux is enabled."
        else
            record_check "$check_id" "WARN" "SELinux disabled"
            log WARN "SELinux is disabled."
            add_doc_link "$check_id" "https://wiki.debian.org/SELinux"
        fi
    else
        record_check "$check_id" "WARN" "No MAC system detected"
        log WARN "No MAC system (AppArmor/SELinux) detected."
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/security-apparmor"
    fi

    # Check 11: Automatic Updates
    check_id="UPDATES"
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        if grep -q "APT::Periodic::Unattended-Upgrade \"1\";" /etc/apt/apt.conf.d/20auto-upgrades; then
            record_check "$check_id" "PASS" "Unattended updates enabled"
            log SUCCESS "Unattended upgrades are enabled."
        else
            record_check "$check_id" "WARN" "Unattended updates disabled"
            log WARN "Unattended upgrades are disabled."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/package-management"
        fi
    else
        record_check "$check_id" "SKIP" "Unattended updates not configured"
        log INFO "Unattended upgrades not configured"
        add_doc_link "$check_id" "https://ubuntu.com/server/docs/package-management"
    fi

    # Check 12: SSH Hardening
    check_id="SSH"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
            record_check "$check_id" "PASS" "SSH root login disabled"
            log SUCCESS "SSH root login is disabled."
        else
            record_check "$check_id" "WARN" "SSH root login enabled"
            log WARN "SSH root login is enabled."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/service-openssh"
        fi
    else
        record_check "$check_id" "SKIP" "SSH config not found"
        log INFO "SSH configuration file not found"
    fi

    # Check 13: Time Synchronization
    check_id="TIME"
    if command_exists timedatectl; then
        if timedatectl status | grep -q "NTP service: active"; then
            record_check "$check_id" "PASS" "NTP service active"
            log SUCCESS "NTP service is active."
        else
            record_check "$check_id" "WARN" "NTP service inactive"
            log WARN "NTP service is not active."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/network-ntp"
        fi
    else
        record_check "$check_id" "SKIP" "Time sync not checked"
        log INFO "Time synchronization not checked (timedatectl missing)"
    fi

    # Check 14: Backup Configuration
    check_id="BACKUP"
    if [ -d /etc/cron.daily ] || [ -d /etc/cron.hourly ]; then
        backup_jobs=$(find /etc/cron.{daily,hourly} -type f 2>/dev/null | wc -l)
        if [ "$backup_jobs" -gt 0 ]; then
            record_check "$check_id" "PASS" "Backup jobs detected ($backup_jobs)"
            log SUCCESS "Backup cron jobs detected."
        else
            record_check "$check_id" "WARN" "No backup jobs configured"
            log WARN "No backup cron jobs detected."
            add_doc_link "$check_id" "https://ubuntu.com/server/docs/backups"
        fi
    else
        record_check "$check_id" "SKIP" "Backup cron not configured"
        log INFO "Cron directories not found"
    fi

    # Check 15: Certbot (SSL)
    check_id="CERTBOT"
    if command_exists certbot; then
        record_check "$check_id" "PASS" "Certbot installed"
        log SUCCESS "Certbot is installed for SSL/TLS certificates."
    else
        record_check "$check_id" "WARN" "Certbot not installed"
        log WARN "Certbot not installed."
        add_doc_link "$check_id" "https://certbot.eff.org/instructions"
    fi

    log INFO "All checks completed"
}

# Generate summary report
generate_summary() {
    echo -e "\n${CYAN}============ ITAM READINESS SUMMARY ============${NC}"
    echo -e "Check Interval: ${GREEN}5 minutes${NC}"
    echo -e "Last Check:    ${GREEN}$(date)${NC}"
    echo -e "${CYAN}===============================================${NC}"
    
    for check_id in "${CHECK_ORDER[@]}"; do
        local status="${CHECK_RESULTS[$check_id]}"
        local message="${CHECK_MESSAGES[$check_id]}"
        
        case "$status" in
            PASS) icon="${GREEN}✓${NC}" ;;
            WARN) icon="${YELLOW}⚠${NC}" ;;
            FAIL) icon="${RED}✗${NC}" ;;
            SKIP) icon="${BLUE}↷${NC}" ;;
            *) icon="${GRAY}?${NC}" ;;
        esac
        
        printf "%-10s ${icon} %s\n" "[$check_id]" "$message"
    done

    echo -e "${CYAN}===============================================${NC}"
    echo -e "Legend: ${GREEN}✓ PASS${NC} | ${YELLOW}⚠ WARN${NC} | ${RED}✗ FAIL${NC} | ${BLUE}↷ SKIP${NC}"
    echo -e "${CYAN}===============================================${NC}"

    # Documentation Summary Section
    if [ ${#DOC_LINKS[@]} -gt 0 ]; then
        echo -e "\n${PURPLE}============ DOCUMENTATION REFERENCES ===========${NC}"
        for check_id in "${!DOC_LINKS[@]}"; do
            echo -e "${YELLOW}$check_id${NC}: ${DOC_LINKS[$check_id]}"
        done
        echo -e "${PURPLE}=================================================${NC}"
    fi
}

# Main execution loop
while true; do
    # Clear previous results
    unset CHECK_RESULTS
    unset CHECK_MESSAGES
    declare -gA CHECK_RESULTS
    declare -gA CHECK_MESSAGES
    
    perform_checks
    generate_summary
    
    # Wait 5 minutes before next run
    log INFO "Next check in 5 minutes..."
    sleep 300
done