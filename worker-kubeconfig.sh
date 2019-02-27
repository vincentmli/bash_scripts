#!/bin/bash

function usage {
            echo "This script creates kubeconfig for  worker node"
	    echo ""
            echo "$0 -h  (this 'help' usage description)"
	    echo ""
            echo "K8S Master Node IP: $0 -m <ip>"
	    echo ""
            echo "K8S Worker Node IP: $0 -w <ip>"
	    echo ""
 	    exit;
}

while getopts "hm:w:" OPTION
do
    case $OPTION in
        m)
            echo "cluster master node ip: $OPTARG"
            K8S_MASTER="$OPTARG"
            ;;
        w)
            echo "cluster worker node ip: $OPTARG"
            K8S_WORKER="$OPTARG"
            ;;
        h)
            usage
            exit
            ;;
        ?)
            usage
            exit
            ;;
    esac
done

if [ "$#" -le 1 ]; then
   usage
fi


KUBE_ROOT=$(dirname "${BASH_SOURCE}")/..

KUBECTL=${KUBECTL:-cluster/kubectl.sh}

source "${KUBE_ROOT}/hack/lib/init.sh"
kube::util::ensure-cfssl

API_PORT=${API_PORT:-8080}
API_SECURE_PORT=${API_SECURE_PORT:-6443}

API_HOST=${API_HOST:-"${K8S_MASTER}"}
API_HOST_IP=${API_HOST_IP:-"${K8S_MASTER}"}

# This is the default dir and filename where the apiserver will generate a self-signed cert
# which should be able to be used as the CA to verify itself
CERT_DIR=${CERT_DIR:-"/var/run/kubernetes"}
ROOT_CA_FILE=${CERT_DIR}/server-ca.crt
ROOT_CA_KEY=${CERT_DIR}/server-ca.key
CLUSTER_SIGNING_CERT_FILE=${CLUSTER_SIGNING_CERT_FILE:-"${ROOT_CA_FILE}"}
CLUSTER_SIGNING_KEY_FILE=${CLUSTER_SIGNING_KEY_FILE:-"${ROOT_CA_KEY}"}


# Ensure CERT_DIR is created for auto-generated crt/key and kubeconfig
mkdir -p "${CERT_DIR}" &>/dev/null || sudo mkdir -p "${CERT_DIR}"
CONTROLPLANE_SUDO=$(test -w "${CERT_DIR}" || echo "sudo -E")


for instance in ${K8S_WORKER}; do

# Create client certs signed with client-ca, given id, given CN and a number of groups
kube::util::create_client_certkey "${CONTROLPLANE_SUDO}" "${CERT_DIR}" 'client-ca' kubelet-${instance} system:node:${instance} system:nodes
kube::util::create_client_certkey "${CONTROLPLANE_SUDO}" "${CERT_DIR}" 'client-ca' kube-proxy-${instance} system:kube-proxy system:nodes

done

for instance in ${K8S_WORKER}; do
  ${KUBECTL} config set-cluster local-up-cluster \
    --certificate-authority="${CERT_DIR}"/server-ca.crt \
    --embed-certs=true \
    --server=https://${K8S_MASTER}:6443 \
    --kubeconfig="${CERT_DIR}"/kubelet-${instance}.kubeconfig

  ${KUBECTL} config set-credentials system:node:${instance} \
    --client-certificate="${CERT_DIR}"/client-kubelet-${instance}.crt \
    --client-key="${CERT_DIR}"/client-kubelet-${instance}.key \
    --embed-certs=true \
    --kubeconfig="${CERT_DIR}"/kubelet-${instance}.kubeconfig

  ${KUBECTL} config set-context local-up-cluster \
    --cluster=local-up-cluster \
    --user=system:node:${instance} \
    --kubeconfig="${CERT_DIR}"/kubelet-${instance}.kubeconfig

  ${KUBECTL} config use-context local-up-cluster --kubeconfig="${CERT_DIR}"/kubelet-${instance}.kubeconfig
done

for instance in ${K8S_WORKER}; do
  ${KUBECTL} config set-cluster local-up-cluster \
    --certificate-authority="${CERT_DIR}"/server-ca.crt \
    --embed-certs=true \
    --server=https://${K8S_MASTER}:6443 \
    --kubeconfig="${CERT_DIR}"/kube-proxy-${instance}.kubeconfig

  ${KUBECTL} config set-credentials system:node:${instance} \
    --client-certificate="${CERT_DIR}"/client-kube-proxy-${instance}.crt \
    --client-key="${CERT_DIR}"/client-kube-proxy-${instance}.key \
    --embed-certs=true \
    --kubeconfig="${CERT_DIR}"/kube-proxy-${instance}.kubeconfig

  ${KUBECTL} config set-context local-up-cluster \
    --cluster=local-up-cluster \
    --user=system:node:${instance} \
    --kubeconfig="${CERT_DIR}"/kube-proxy-${instance}.kubeconfig

  ${KUBECTL} config use-context local-up-cluster --kubeconfig="${CERT_DIR}"/kube-proxy-${instance}.kubeconfig
done


echo ""
echo "Remember to setup ssh authorization between master and worker node"
echo "copy kubeconfig to worker node ${K8S_WORKER} "
echo ""

ssh ${K8S_WORKER} 'rm -rf /var/run/kubernetes; mkdir /var/run/kubernetes'

/usr/bin/scp /var/run/kubernetes/*${K8S_WORKER}.kubeconfig root@${K8S_WORKER}:/var/run/kubernetes/
