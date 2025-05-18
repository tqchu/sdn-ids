# add bridge
sudo ovs-vsctl add-br br1
# add port
sudo ovs-vsctl add-port br1 enp0s31f6
# del bridge
sudo ovs-vsctl del-br br1
# del port
sudo ovs-vsctl del-port enp0s31f6
# show info
sudo ovs-vsctl show

sudo ovs-ofctl add-flow br0 actions=normal

sudo ovs-vsctl set-controller br0 tcp:10.50.50.2:6653
sudo ovs-vsctl add-port br0 enp0s31f6
