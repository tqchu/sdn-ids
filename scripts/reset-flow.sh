sudo ovs-ofctl del-flows br0
sudo ovs-ofctl add-flow br0 "priority=10,ip,icmp,actions=NORMAL"