sudo ip route add default via 10.50.50.2

# On VM 10.50.50.4
# Avoid Direct Layer 2 communication
sudo ip addr del 10.50.50.4/24 dev eth0
sudo ip addr add 10.50.50.4/32 dev eth0
sudo ip route add 10.50.50.2 dev eth0
sudo ip route add default via 10.50.50.2

sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0