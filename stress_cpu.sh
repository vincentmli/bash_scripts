#!/bin/bash

i=0

dd if=/dev/urandom of=/tmp/testfile count=20 bs=1024k

while [ 1 ]
do
   md5sum /tmp/testfile >> /dev/null
   i=`expr $i + 1`
   echo "Iteration: $i" >> /dev/null
done
~
