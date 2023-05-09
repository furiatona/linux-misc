#!/bin/sh -e

# Author: Dheny @furiatona on github
# Generate Exim queue number
# which are not handled by node_exporter's own collector

# Sample output
# [root@example.local ~]# exim -bpc
# 55

EXIM_QCOUNT=$(timeout 5 exim -bpc)

exim_queue $EXIM_QCOUNT
