#!/bin/bash

# Find out random unused TCP port
findRandomTcpPort(){
        port=$(( 100+( $(od -An -N2 -i /dev/random) )%(1023+1) ))
        while :
        do
                (echo >/dev/tcp/localhost/$port) &>/dev/null &&  port=$(( 100+( $(od -An -N2 -i /dev/random) )%(1023+1) )) || break
        done
        echo "$port"
}

p=$(findRandomTcpPort)


for((j=1; j<=10; j++))
 do
   echo $j
  for ((i=22; i<=254; i++))
   do
    echo $i
    /usr/bin/tmsh create /ltm  virtual SR-122907411-$p destination 10.99.99.$i:$p  profiles add { tcp http } pool { a_pool100 } snat automap
   done
done
