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