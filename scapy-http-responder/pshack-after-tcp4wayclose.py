#!/usr/bin/python
'''
act like simple http client to establish 3WHS with http server and ack data from server 
https://tron.f5net.com/sr/1-1884722351/

@author: Vincent Li 
'''
from scapy import all
from scapy.layers.inet import IP, ICMP, TCP
from scapy.packet import ls, Raw
from scapy.sendrecv import sniff, send
from time import sleep
import scapy.all
import random
HOSTADDR = "10.1.72.93"
TCPPORT = 8401
SEQ_NUM = 100
SRCPORT =random.randint(1045, 65000)

get='GET / HTTP/1.0\n\n'


def tcp_monitor_callback(pkt):
    global SEQ_NUM
    global TCPPORT
    global HOSTADDR
    global COUNT
    global PSHACK

    if(pkt.payload.payload.flags & 2 != 0):
        'A syn + ack situation, for SYN + ACK'
        print("tcp incoming connection")
        ACK=TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A",ack=pkt[TCP].seq + 1,seq=pkt[TCP].ack)/get
        PSHACK=TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A",ack=pkt[TCP].seq + 1,seq=pkt[TCP].ack)/get
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/ACK)
    elif(pkt.payload.payload.flags & 8 !=0):
        'accept push from server, 8 for PSH flag'
        print("tcp push connection from server")
        pushLen = pkt[IP].len - (pkt[IP].ihl * 4 + pkt[TCP].dataofs * 4) 
	ACK1win1448=TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="FA", ack=pkt[TCP].seq + pushLen,seq=pkt[TCP].ack,window=1448)
       	send(IP(src=pkt[IP].dst,dst=pkt[IP].src)/ACK1win1448)

    elif(pkt.payload.payload.flags & 1 !=0):
        'accept fin from server'
        print ("tcp server fin connection")
        LAST_ACK=TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="A", ack=pkt[TCP].seq +1, seq = pkt[TCP].ack)
        send(IP(src=pkt[IP].dst,dst=pkt[IP].src)/LAST_ACK)
	sleep(0.8)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/PSHACK)
def dispatcher_callback(pkt):
    print "packet incoming"
    global HOSTADDR
    global TCPPORT

    if(pkt.haslayer(TCP) and (pkt[TCP].sport == TCPPORT)):
        tcp_monitor_callback(pkt)
    else:
        return
if __name__ == '__main__':
    print "Simple scapy http client "
    scapy.all.conf.iface = "eth2"
    ip=IP(dst=HOSTADDR)
    SYN=ip/TCP(sport=SRCPORT, dport=TCPPORT, flags="S", options=[('Timestamp',(0,0))])
    #SYN=ip/TCP(sport=12340, dport=80, flags="S")
    # Send SYN and receive SYN,ACK
    print "\n[*] Sending our SYN packet"
    send(SYN)
    sniff(filter=("port %s") % (TCPPORT), prn=dispatcher_callback)

