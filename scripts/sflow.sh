# get config
sudo ovs-vsctl list sflow
# clear config
sudo ovs-vsctl clear bridge br0 sflow

sudo ovs-vsctl -- --id=@sflow create sflow agent=wlp0s20f3     target=\"localhost:6343\" sampling=4 polling=10     -- set bridge br0 sflow=@sflow