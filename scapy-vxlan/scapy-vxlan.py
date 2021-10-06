#!/usr/bin/python3

#CiliumNode IP:    10.169.72.233
#LinuxVM    IP:    10.169.72.236
#PodCIDR:          10.0.0.0/16
#ExernalVxlanCIDR: 10.1.1.0/24
#busybox:          10.0.1.1/24

# Enable cilium external VXLAN tunne device integration

#  CiliumNode
#
#  enable-external-vxlan:   "true"
#  external-vxlan-endpoint: "10.169.72.236"
#  external-vxlan-cidr:     "10.1.1.0/24"
#  external-vxlan-mac:      "82:36:4c:98:2e:56"
#
#  start ping test from busybox pod
#  kubectl exec -it busybox -- ping -c 10 10.1.1.2

#  Linux VM
#  1 change scapy-vxlan sniff interface to ens192 for example
#  2 change DSTHOST to ens192 interface IP
#  3 run ./scapy-vxlan
#
#     Test external VXLAN tunnel device packet flow
#+--------------------------+
#|                          |            +-----------------+
#| CiliumNode               |            |  Linux VM       |
#|                          |            |                 |
#|  +---------+             |            | ./scapy-vxlan   |
#|  | busybox |             |            |                 |
#|  |         |           ens192<------>ens192             |
#|  +--eth0---+             |            |                 |
#|      |                   |            +-----------------+
#|      |                   |
#|   lxcxxx                 |
#|      |                   |
#+------+-----cilium_vxlan--+

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

#Having trouble to set the flags here 0x0800 result 0 flags and 0xC
#The packet will be handled by Cilium BPF attached to netdev, but then
#Packet get dropped somewhere, maybe in the kernel, so here use the
#incoming VXLAN flags to set the VXLAN flags, which is 0x0800 and resolved
#the packet VXLAN packet dropping issue.
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