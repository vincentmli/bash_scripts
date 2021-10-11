#!/usr/bin/python3
#
#     How to test external VXLAN tunnel devices integration
#
#     TEST Dependencies
#
#     1. One Virtual Machine with Linux distribution (Ubuntu 20.04 tested)
#     2. Please reference https://docs.cilium.io/en/stable/gettingstarted/kind/
#        for Cilium deployment in kind dependencies
#     3. Install python3-scapy package
#
#              Diagram
#
#            KIND (K8S in Docker)
#
# +------------------------------------------------------------------------+
# |                                              Host(initns)              |
# |      +------------------------------+    +--------------------+        |
# |      |                              |    |                    |        |
# |      |  K8S control node            |    | K8S worker node    |        |
# |      |                              |    |                    |        |
# |      |  +--------+ vxlanCIDR:       |    |                    |        |
# |      |  |busybox |    10.1.5.0/24   |    |                    |        |
# |      |  |        | vxlanEndpoint:   |    |                    |        |
# |      |  +-eth0---+    172.18.0.1    |    |                    |        |
# |      |     |       vxlanMAC:        |    |                    |        |
# |      |     |         x:x:x:x:x:x:x  |    |                    |        |
# |      |    lxcxxx@if                 |    |                    |        |
# |      |     |                        |    |                    |        |
# |      |     |                        |    |                    |        |
# |      |     +---cilium_vxlan--+      |    |                    |        |
# |      |                       |      |    |                    |        |
# |      |                       |      |    |  172.18.0.3        |        |
# |      +----------------------veth0---+    +------veth0---------+        |
# |         172.18.0.2            |                  |                     |
# |                             veth1               veth2                  |
# |                               |                  |                     |
# |  kubectl exec -it \           |                  |                     |
# |    <busybox> -- \             +-----------br0----+                     |
# |    ping 10.1.5.1                       172.18.0.1                      |
# |                                       ./external-vxlan.py sniff        |
# |                                        on host bridge interface        |
# +------------------------------------------------------------------------+
#
#
#    External VXLAN tunnel devices integration test steps
#
#    1. Deploy kind cluster with one control plane node
#
#    # cat kind-cluster.yaml
#    kind: Cluster
#    apiVersion: kind.x-k8s.io/v1alpha4
#    nodes:
#    - role: control-plane
#    networking:
#      disableDefaultCNI: true
#
#    # kind create cluster --config=kind-cluster.yaml
#
#    2.  Deploy Cilium in KIND k8s control plane node with feature enabled

#    # helm install cilium cilium/cilium --version <cilium version> \
#         --namespace kube-system \
#         --set externalVxlan.enabled=true \
#         --set externalVxlan.endpoint="172.18.0.1" \
#         --set externalVxlan.CIDR="10.1.5.0/24" \
#         --set externalVxlan.MAC="00:50:56:A0:7D:D8" \
#         --set kubeProxyReplacement=partial \
#         --set hostServices.enabled=false \
#         --set externalIPs.enabled=true \
#         --set nodePort.enabled=true \
#         --set hostPort.enabled=true \
#         --set bpf.masquerade=false \
#         --set image.pullPolicy=IfNotPresent \
#         --set ipam.mode=kubernetes
#
#    3. docker pull the image and load in kind
#
#     # docker pull cilium/cilium:<version>
#     # kind load docker-image cilium/cilium:<version>
#
#    4. deploy busybox on kind control plaine node
#
#    # kubectl label node kind-control-plane  dedicated=master
#    # kubectl taint nodes --all node-role.kubernetes.io/master-
#    # cat busybox-master.yaml
#    apiVersion: v1
#    kind: Pod
#    metadata:
#      name: busybox-master
#      labels:
#        app: busybox
#    spec:
#      nodeSelector:
#        dedicated: master
#      containers:
#      - name: busybox
#        image: busybox
#        imagePullPolicy: IfNotPresent
#        command: ['sh', '-c', 'echo Container 1 is Running ; sleep 3600']
#
#     # kubectl apply -f busybox-master.yaml
#
#    5. Deploy external-vxlan.py in systemd service and startup
#       external-vxlan service
#
#      when kind cluster is up, check VM host bridge interface name
#      and change external-vxlan.py script to sniff on the bridge interface
#      for example "br-22b28ede79c2"
#
#      # cat /etc/systemd/system/external-vxlan.service
#     [Unit]
#     Description=Spark service
#
#     [Service]
#     ExecStart=/usr/local/bin/external-vxlan.py
#
#     [Install]
#     WantedBy=multi-user.target
#
#     # systemctl enable external-vxlan.service
#     # systemctl start external-vxlan.service
#
#    6. Ping from busybox to IP 10.1.5.1 within external VXLAN CIDR 10.1.5.0/24
#
#    # kubectl exec -it busybox-master  -- ping -c 10 10.1.5.1
#
#
from scapy import all
from scapy.layers import all
from scapy.layers.inet import IP, ICMP, UDP
from scapy.packet import ls, Raw
from scapy.sendrecv import sniff, send
from scapy.all import *
UDPPORT = 8472
SRCPORT = 55555
DSTHOST = "172.18.0.1"
INNERIP = "10.1.5.1"
VNI = 2
PAYLOAD='zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'


def udp_monitor_callback(pkt):
    global UDPPORT
    global SRCPORT
    global VNI
    inLayer3 = pkt.payload.payload.payload.payload.payload

#only respond when ping destination IP matches external VXLAN IP address
    if(pkt.haslayer(IP) and inLayer3.dst == INNERIP):
        print("incoming IP packet matches",  INNERIP)
        outLayer3 = pkt.payload
        udpLayer = pkt.payload.payload
        vxlanLayer = pkt.payload.payload.payload
        inLayer2 = pkt.payload.payload.payload.payload
        inLayer4 = pkt.payload.payload.payload.payload.payload.payload

        outerIP=IP(src=outLayer3.dst, dst=outLayer3.src)

        udpinfo=UDP(sport=SRCPORT, dport=UDPPORT)

#Having trouble to set the flags here 0x0800 result 0 flags and 0xC
#The packet will be handled by Cilium BPF attached to netdev, but then
#Packet get dropped somewhere, maybe in the kernel, so here use the
#incoming VXLAN flags to set the VXLAN flags, which is 0x0800 and resolved
#the packet VXLAN packet dropping issue.
        vxlan=VXLAN(flags=vxlanLayer.flags, vni=VNI)

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
    scapy.all.conf.iface = "br-22b28ede79c2"
    sniff(filter=("port %s") % (UDPPORT), prn=dispatcher_callback)
