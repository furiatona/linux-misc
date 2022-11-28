#!/bin/sh -e

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

# Command /opt/MegaRAID/MegaCli/MegaCli64 -LDInfo -Lall -aAll
STATUS=""

HW_RAID_INFO=$(/opt/MegaRAID/MegaCli/MegaCli64 -LDInfo -Lall -aAll)
NAME=$(echo "$HW_RAID_INFO" | grep Name | awk '{print $NF}' | sed 's/://g')
STATUS=$(echo "$HW_RAID_INFO" | grep State | awk '{print $NF}' | sed 's/://g')

if [ $STATUS == "Optimal" ] ; then
    STATUS=1
else
    STATUS=0
fi

cat <<EOS
hw_raid_info{name="$NAME"} $STATUS
EOS