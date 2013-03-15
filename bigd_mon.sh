#!/bin/bash

bigd_cpu_thresh=50
echo "waiting to see if bigd contiues consume $bigd_cpu_thresh% cpu , if so, start strace bigd"

while true;
do
cpu_t1=`top -cbn1 | grep '/usr/bin/bigd' | grep -v grep | awk '{print $9;}' | cut -d'.' -f1`
echo "cpu_t1 $cpu_t1"
if [ $cpu_t1 -ge $bigd_cpu_thresh ] 
  then
     sleep 1 
     cpu_t2=`top -cbn1 | grep '/usr/bin/bigd' | grep -v grep | awk '{print $9;}' | cut -d'.' -f1`
     pid_t2=`top -cbn1 | grep '/usr/bin/bigd' | grep -v grep | awk '{print $1;}'`
     echo "cpu_t2 $cpu_t2"
#     echo "pid_t2 $pid_t2"
     if [ $cpu_t2 -ge $bigd_cpu_thresh ]
        then 
           echo "bigd consumes $bigd_cpu_thresh% cpu, break the loop and start strace $pid_t2"
           strace -o /var/tmp/bigd-$pid_t2.out  -p $pid_t2
           break
     fi
fi
sleep 1;
done

