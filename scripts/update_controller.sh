# bring down all
sudo ovs-vsctl del-port br0 enp0s31f6
sudo ovs-vsctl del-br br0
sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 enp0s31f6
sudo ip link set enp0s31f6 down
sudo ip addr flush dev enp0s31f6
sudo ip addr add 10.50.50.2/24 dev br0
sudo ip link set br0 up
sudo ovs-vsctl set-controller br0 tcp:localhost:6653
sudo ip link set enp0s31f6 up


sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.conf.br0.send_redirects=0
sudo sysctl -w net.ipv4.conf.enp0s31f6.send_redirects=0