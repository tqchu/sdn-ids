#!/usr/bin/env bash
# This script brings up VMs, set IPs config for VMs
# It also configures the SDN controller and the Open vSwitch bridge
# Its up snort in daemon mode if provided with --snort flag, else run the AI detector
# And start the traffic logger controller

set -euo pipefail

vmrun start '/home/truongchu/VirtualMachines/Metasploitable2Linux/Metasploitable.vmx'
#vmrun start '/home/truongchu/.vagrant.d/boxes/rapid7-VAGRANTSLASH-metasploitable3-ub1404/0.1.12-weekly/vmware_desktop/metasploitable3-ub1404.vmx'
#vmrun start '/home/truongchu/.vagrant.d/boxes/rapid7-VAGRANTSLASH-metasploitable3-win2k8/0.1.0-weekly/vmware_desktop/metasploitable3-win2k8.vmx'

sleep 30

sshpass -p 'msfadmin' \
  ssh -o StrictHostKeyChecking=no \
      msfadmin@198.51.100.128 \
      'echo msfadmin | sudo -S ip route add default via 198.51.100.1'

#sshpass -p 'vagrant' \
#  ssh -o StrictHostKeyChecking=no \
#      vagrant@10.50.50.128 \
#      'echo vagrant | sudo -S ip route add default via 10.50.50.1'

sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 vmnet2
sudo ovs-vsctl add-port br0 vmnet3
sudo ip addr flush dev vmnet2
sudo ip addr flush dev vmnet3

sudo ip addr add 10.50.50.1/24 dev br0
sudo ip addr add 198.51.100.1/24 dev br0

sudo ip link set br0 up
sudo ovs-vsctl set-controller br0 tcp:localhost:6653
sudo ovs-ofctl add-flow br0 "priority=10,ip,icmp,actions=NORMAL"


# Parse flags
SNORT=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --snort)
      SNORT=true
      shift
      ;;
    *)
      echo "Usage: $0 [--snort]"
      exit 1
      ;;
  esac
done

# If requested, bring up Snort first
if $SNORT; then
  echo "[*] Starting Snort infrastructure…"
  scripts/up_snort.sh
  echo "[*] Snort is up."
fi

sudo ip link add veth-mininet type veth peer name veth-ovs
sudo ip link set veth-mininet up
sudo ip link set veth-ovs up

sudo ovs-vsctl add-port br0 veth-ovs

goflow2_container_id=$(docker run -d --name goflow2 --network controller_default -p 6343:6343/udp goflow2)
echo "Goflow2 container ID: $goflow2_container_id"

consumer_container_id=$(docker run -d --name ml_detector   --network controller_default   -v $(pwd)/flows:/app/flows   -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092   -e PUSHGATEWAY_URL=pushgateway:9091   -e LOKI_URL=http://loki:3100 -e CONTROLLER_HOST=172.17.0.1  ml-detector-final)
echo "ML Detector container ID: $consumer_container_id"

#msfrpcd -U msf -P truongquangchu -p 55553

sudo ovs-vsctl -- --id=@sflow create sflow agent=wlp0s20f3     target=\"localhost:6343\" sampling=1 polling=5     -- set bridge br0 sflow=@sflow
export PYTHONPATH=$(pwd):$PYTHONPATH

#ryu-manager controller.traffic_logger
ryu-manager  --wsapi-port 8082 controller.flow_controller ryu.app.ofctl_rest


# up the consumer
# up the sflow collector

# up the consumer
#python3 -m controller.consumer

