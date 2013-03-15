#!/bin/bash
# Set a trap to detect spam bots at port 80
 
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
echo "Setting Honeypot @ port 80 and real Apache server at port $p..."
