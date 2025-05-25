#!/bin/bash

# Author: Dheny @furiatona on github
# Generate nvme status for node_exporter custom metrics

# Export path
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Pre-check
if ! command -v smartctl &> /dev/null || ! command -v nvme &> /dev/null || ! systemctl is-active --quiet node_exporter; then
    echo "One or more required conditions are not met. Please check the systems."
    exit 1
fi

# Get all NVMe devices
nvme_list=$(nvme list | awk '/^\/dev\/nvme/ {print $1}')
nvme_count=$(echo "$nvme_list" | wc -w)

# Output nvme_disk_count
echo "nvme_disk_count $nvme_count"

# For each NVMe device, get health status
for nvme in $nvme_list; do
    # Ensure smartctl can access it
    if smartctl -a "$nvme" &> /dev/null; then
        nvme_status=$(smartctl -a "$nvme" | awk -F: '/Critical Warning/{gsub(/ /, "", $2); print $2}')
        nvme_util=$(smartctl -a "$nvme" | awk -F: '/Percentage Used/{gsub(/ /, "", $2); gsub(/%/, "", $2); print $2}')
        
        # If smartctl didn't return values properly, skip this disk
        if [[ -z "$nvme_status" || -z "$nvme_util" ]]; then
            continue
        fi
        
        nvme_lifetime=$((100 - nvme_util))
        nvme_disk_avail=$([[ "$nvme_status" == "0x00" ]] && echo 1 || echo 0)
        
        echo "nvme_disk_avail{name=\"$nvme\"} $nvme_disk_avail"
        echo "nvme_disk_util{name=\"$nvme\"} $nvme_lifetime"
    fi
done