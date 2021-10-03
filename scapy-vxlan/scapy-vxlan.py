#!/usr/bin/python3

from scapy import all
from scapy.layers import all
from scapy.layers.inet import IP, ICMP, UDP
from scapy.packet import ls, Raw
from scapy.sendrecv import sniff, send
from scapy.all import *
UDPPORT = 8472
SRCPORT = 55555
DSTHOST = "10.169.72.236"
PAYLOAD='zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'


def udp_monitor_callback(pkt):
    global UDPPORT
    global SRCPORT

    if(pkt.haslayer(IP)):
        print("incoming IP packet")
        outLayer3 = pkt.payload
        udpLayer = pkt.payload.payload
        vxlanLayer = pkt.payload.payload.payload
        inLayer2 = pkt.payload.payload.payload.payload
        inLayer3 = pkt.payload.payload.payload.payload.payload
        inLayer4 = pkt.payload.payload.payload.payload.payload.payload

        outerIP=IP(src=outLayer3.dst, dst=outLayer3.src)

        udpinfo=UDP(sport=SRCPORT, dport=UDPPORT)

        vxlan=VXLAN(flags=vxlanLayer.flags, vni=2)

        innerETH=Ether(dst=inLayer2.src, src=inLayer2.dst, type=0x800)

        innerIP=IP(src=inLayer3.dst,dst=inLayer3.src)

        innerICMP=ICMP(type=0, code=0, id=inLayer4.id, seq=inLayer4.seq)

        send(outerIP/udpinfo/vxlan/innerETH/innerIP/innerICMP/PAYLOAD)

    if(pkt.haslayer(ARP)):
        print("incoming ARP packet")

def dispatcher_callback(pkt):
    global UDPPORT
    global DSTHOST
    if(pkt.haslayer(UDP) and (pkt[UDP].dport == UDPPORT) and (pkt[IP].dst == DSTHOST)):
        print("incoming VXLAN packet")
        udp_monitor_callback(pkt)
    else:
        return
if __name__ == '__main__':
    print("Scapy vxlan responder")
    scapy.all.conf.iface = "ens192"
    sniff(filter=("port %s") % (UDPPORT), prn=dispatcher_callback)
