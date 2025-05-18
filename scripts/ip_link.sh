#
sudo ip link set br-p1 up
#
sudo ip link set enp0s31f6 up
#
sudo brctl addif br-p1 enp0s31f6
#
ip link show enp0s31f6
#
brctl show
#
 sudo brctl addbr br-p1
#
sudo ip addr add 10.50.50.2/24 dev enp0s31f6
#
sudo ethtool enp0s31f6

sudo ip link set enp0s31f6 up

sudo ip addr flush dev enp0s31f6