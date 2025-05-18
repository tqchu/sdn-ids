# enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1
# configure NAT
sudo iptables -t nat -A POSTROUTING -s 10.50.50.0/24 ! -d 10.50.50.0/24 -o wlp0s20f3 -j MASQUERADE

sudo ovs-ofctl del-flows br0
sudo ovs-ofctl add-flow br0 "priority=0,actions=NORMAL"
#sudo iptables -t nat -D POSTROUTING -s 192.168.10.0/24 -o eth0   -j MASQUERADE
#sudo iptables -t nat -D POSTROUTING -s 192.168.10.0/24 -o wlp0s20f3 -j MASQUERADE
