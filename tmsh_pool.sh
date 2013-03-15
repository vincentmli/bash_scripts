#!/bin/bash
for ((i=12; i<=254; i++))
do
echo $i
/usr/bin/tmsh modify /ltm pool  C1072139-2_pool members add { 10.1.70.$i:80 } 
done
