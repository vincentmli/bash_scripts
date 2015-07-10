#!/usr/bin/python
'''
act like simple http server to send sequence of predefined response
to simulate customers case
https://tron.f5net.com/sr/1-1297458280/

@author: Vincent Li 
'''
from scapy import all
from scapy.layers.inet import IP, ICMP, TCP
from scapy.packet import ls, Raw
from scapy.sendrecv import sniff, send
import scapy.all
HOSTADDR = "10.1.72.8"
TCPPORT = 80 
SEQ_NUM = 100

with open("frame8.txt", "r") as myframe8:
    get8=myframe8.read()

with open("frame10.txt", "r") as myframe10:
    get10=myframe10.read()

with open("frame11.txt", "r") as myframe11:
    get11=myframe11.read()

with open("frame13.txt", "r") as myframe13:
    get13=myframe13.read()



def tcp_monitor_callback(pkt):
    global SEQ_NUM
    global TCPPORT
    if(pkt.payload.payload.flags == 2):
        'A syn situation, 2 for SYN'
        print("tcp incoming connection")
        ACK=TCP(sport=TCPPORT, dport=pkt.payload.payload.sport, flags="SA",ack=pkt.payload.payload.seq + 1,seq=0)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/ACK)
    if(pkt.payload.payload.flags & 8 !=0):
        'accept push from client, 8 for PSH flag'
        print("tcp push connection")
        pushLen = pkt[IP].len - (pkt[IP].ihl * 4 + pkt[TCP].dataofs * 4) 
        fr8=TCP(sport=TCPPORT, dport=pkt[TCP].sport, flags="PA", ack=pkt[TCP].seq + pushLen,seq=pkt[TCP].ack)/get8
        fr10=TCP(sport=TCPPORT, dport=pkt[TCP].sport, flags="PA", ack=pkt[TCP].seq + pushLen,seq=pkt[TCP].ack + len(get8))/get10
        fr11=TCP(sport=TCPPORT, dport=pkt[TCP].sport, flags="PA", ack=pkt[TCP].seq + pushLen,seq=pkt[TCP].ack + len(get8) + len(get10))/get11
        fr13=TCP(sport=TCPPORT, dport=pkt[TCP].sport, flags="PA", ack=pkt[TCP].seq + pushLen,seq=pkt[TCP].ack + len(get8) + len(get10) + len(get11))/get13
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/fr8)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/fr10)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/fr11)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/fr13)
    if(pkt.payload.payload.flags & 1 !=0):
        'accept fin from cilent'
        print ("tcp fin connection")
        FIN=TCP(sport=TCPPORT, dport=pkt.payload.payload.sport, flags="FA", ack=pkt.payload.payload.seq +1, seq = pkt.payload.payload.ack)
        send(IP(src=pkt.payload.dst,dst=pkt.payload.src)/FIN)
def dispatcher_callback(pkt):
    print "packet incoming"
    global HOSTADDR
    global TCPPORT
    #if(pkt.haslayer(TCP) and (pkt.payload.dst == HOSTADDR) and (pkt.payload.dport == TCPPORT)):
    if(pkt.haslayer(TCP) and (pkt.payload.dport == TCPPORT)):
        tcp_monitor_callback(pkt)
    else:
        return
if __name__ == '__main__':
    print "Simple scapy http responder "
    scapy.all.conf.iface = "eth0"
    sniff(filter=("port %s") % (TCPPORT), prn=dispatcher_callback)
