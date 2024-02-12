#!/bin/bash

# Author: Dheny @furiatona on github
# Generate nvme status
# which are not handled by node_exporter's own collector

# Export path
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Preliminaries for NVME
if ! command -v smartctl &> /dev/null || ! command -v nvme &> /dev/null || ! systemctl is-active --quiet node_exporter; then
    echo "One or more required conditions are not met. Please check the systems."
    exit 1
fi

# Count NVMe disks with brand "Samsung"
nvme_list=$(nvme list | grep "Samsung" | awk '{print $1}'  2>/dev/null)
nvme_count=$(echo $nvme_list | wc -w 2>/dev/null)

# If the above command fails, set count to 0
if [ $? -ne 0 ]; then
    nvme_count=0
fi

# If nvme_count is 0, use the pvs command to double check the PV
if [ $nvme_count -eq 0 ]; then
    nvme_count=$(pvs | grep -c "solusvm" 2>/dev/null)
    if [ $? -ne 0 ]; then
        nvme_count=0
    fi
fi
cat <<EOS
nvme_disk_count $nvme_count
EOS

# Check the nvme status
if [ $nvme_count -ne 0 ]; then
    for nvme in $nvme_list; do
        nvme_status=$(smartctl -a $nvme | grep Critical\ Warning | awk -F': ' '{print $2}' | awk '{$1=$1;print}')
        nvme_util=$(smartctl -a $nvme | grep Percentage | awk -F': ' '{print $2}' | awk '{$1=$1;print}' | tr -d '%')
        nvme_lifetime=$((100 - $nvme_util))
        if [ $nvme_status != "0x00" ]; then
            nvme_disk_avail=0
        else
            nvme_disk_avail=1
        fi
cat <<EOS
nvme_disk_avail{name="$nvme"} $nvme_disk_avail
nvme_disk_util{name="$nvme"} $nvme_lifetime
EOS
    done
fi