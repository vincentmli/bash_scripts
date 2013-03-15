#!/bin/bash
bigstart stop tmm
opcontrol --deinit
opcontrol --no-vmlinux --separate=kernel
opcontrol --init
opcontrol --reset
opcontrol --start
bigstart start tmm
echo "start profiling tmm for 180 mintues"
sleep 180
echo "start profiling tmm for 180 mintues"
echo "tmm profiling report"

opreport -l /usr/bin/tmm64.default > /var/tmp/tmm-oprofile-`date +%H-%M-%S`.txt
