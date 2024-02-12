#!/bin/bash

# Author: Dheny @furiatona on github
# Generate hardware raid status
# which are not handled by node_exporter's own collector

# Sample output
# Name                : DXDS600_R10
# RAID Level          : Primary-1, Secondary-0, RAID Level Qualifier-0
# Size                : 7.275 TB
# Sector Size         : 512
# Mirror Data         : 7.275 TB
# State               : Optimal

# Export path
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

######################## MEGA ##############################
STATUS=""
HW_RAID_INFO=$(/opt/MegaRAID/MegaCli/MegaCli64 -LDInfo -Lall -aAll 2>/dev/null)
NAME=$(echo "$HW_RAID_INFO" | grep Name | awk '{print $NF}' | sed 's/://g')
STATUS=$(echo "$HW_RAID_INFO" | grep State | awk '{print $NF}' | sed 's/://g')

if [ -n "$STATUS" ]; then
    if [ "$STATUS" = "Optimal" ]; then
cat <<EOS
hw_raid_info{name="$NAME"} 1
EOS
    else
cat <<EOS
hw_raid_info{name="$NAME"} 0
EOS
    fi
fi

######################## NVME ##############################

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
        if [ $nvme_status != "0x00" ]; then
            nvme_disk_avail=0
        else
            nvme_disk_avail=1
        fi
cat <<EOS
nvme_disk_avail{name="$nvme"} $nvme_disk_avail
nvme_disk_util{name="$nvme"} $nvme_util
EOS
    done
fi