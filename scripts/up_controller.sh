set -euo pipefail

sshpass -p 'msfadmin' ssh -o StrictHostKeyChecking=no \
  msfadmin@198.51.100.128 \
  "echo msfadmin | sudo -S ip route replace default via 198.51.100.130"
echo "Configured default route ok"
# sshpass -p 'vagrant' \
#   ssh -o StrictHostKeyChecking=no \
#       vagrant@10.50.50.128 \
#       'echo vagrant | sudo -S ip route add default via 10.50.50.1'

sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 ens33
#sudo ovs-vsctl add-port br0 vmnet3
# sudo ip addr flush dev vmnet2
sudo ip addr flush dev ens33

# sudo ip addr add 10.50.50.1/24 dev br0
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

goflow2_container_id=$(docker run -d --name goflow2 --network sdn-ids_default -p 6343:6343/udp truongquangchu/goflow2)
echo "Goflow2 container ID: $goflow2_container_id"

consumer_container_id=$(docker run -d --name ml_detector   --network sdn-ids_default   -v $(pwd)/flows:/app/flows   -e KAFKA_BOOTSTRAP_SERVERS=kafka:29092   -e PUSHGATEWAY_URL=pushgateway:9091   -e LOKI_URL=http://loki:3100 -e CONTROLLER_HOST=172.17.0.1 -e DPID=0000000c29bb448a truongquangchu/ml-detector)
echo "ML Detector container ID: $consumer_container_id"

sudo ovs-vsctl -- --id=@sflow create sflow agent=ens33     target=\"localhost:6343\" sampling=4 polling=10     -- set bridge br0 sflow=@sflow
export PYTHONPATH=$(pwd):${PYTHONPATH:-}
#ryu-manager controller.traffic_logger
ryu-manager  --wsapi-port 8082 controller.flow_controller ryu.app.ofctl_rest