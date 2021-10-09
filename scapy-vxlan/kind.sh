#!/bin/bash

# 1 create kind cluster
#kind create cluster --config=kind-cluster.yaml -v 9
kind create cluster --config=kind-cluster.yaml

# 2 install cilium

helm repo add cilium https://helm.cilium.io/

helm template cilium cilium/cilium --version 1.10.4 \
   --namespace kube-system \
   --set nodeinit.enabled=true \
   --set kubeProxyReplacement=partial \
   --set hostServices.enabled=false \
   --set externalIPs.enabled=true \
   --set nodePort.enabled=true \
   --set hostPort.enabled=true \
   --set bpf.masquerade=false \
   --set image.pullPolicy=IfNotPresent \
   --set ipam.mode=kubernetes > cilium.yaml


# manually edit cilium.yaml to add external VXLAN in configmap cilium-config
# change image location, this is not needed when feature merged in upstream
# use helm below should do it

#helm template cilium cilium/cilium --version <cilium version> \
#   --namespace kube-system \

#   --set externalVxlan.enabled=true \
#   --set externalVxlan.endpoint="172.18.0.1" \
#   --set externalVxlan.CIDR="10.1.5.0/24" \
#   --set externalVxlan.MAC="00:50:56:A0:7D:D8" \
#
#   --set kubeProxyReplacement=partial \
#   --set hostServices.enabled=false \
#   --set externalIPs.enabled=true \
#   --set nodePort.enabled=true \
#   --set hostPort.enabled=true \
#   --set bpf.masquerade=false \
#   --set image.pullPolicy=IfNotPresent \
#   --set ipam.mode=kubernetes > cilium.yaml

# docker pull the image and load in kind
docker pull vli39/cilium:ipcache
kind load docker-image vli39/cilium:ipcache

# deploy cilium
kubectl apply -f cilium-ipcache.yaml

# 3 deploy busybox on kind control plaine node

kubectl label node kind-control-plane  dedicated=master
kubectl taint nodes --all node-role.kubernetes.io/master-

kubectl apply -f busybox-master.yaml
