#!/bin/sh -e

# Author: Dheny @furiatona on github
# Generate Exim queue number
# which are not handled by node_exporter's own collector

# Sample output
# [root@example.local ~]# exim -bpc
# 55

EXIM_CMD=$(/usr/sbin/exim -bpc)
CMD_TIMEOUT="/usr/bin/timeout 5"

$CMD_TIMEOUT /usr/sbin/exim -bpc > /dev/null
exit_status=$?
if [[ $exit_status -eq 124 ]]; then
cat <<EOS
exim_queue 999999999
EOS
else
cat <<EOS
exim_queue $EXIM_CMD
EOS
fi