vmrun stop '/home/truongchu/VirtualMachines/Metasploitable2Linux/Metasploitable.vmx'
vmrun stop '/home/truongchu/.vagrant.d/boxes/rapid7-VAGRANTSLASH-metasploitable3-ub1404/0.1.12-weekly/vmware_desktop/metasploitable3-ub1404.vmx'
vmrun stop '/home/truongchu/.vagrant.d/boxes/rapid7-VAGRANTSLASH-metasploitable3-win2k8/0.1.0-weekly/vmware_desktop/metasploitable3-win2k8.vmx'

sudo ovs-vsctl del-br br0
sudo ip addr flush dev br0

sudo ip addr add 198.51.100.1/24 dev vmnet2
sudo ip addr add 10.50.50.1/24 dev vmnet3

sudo ip link set vmnet2 up
sudo ip link set vmnet3 up

sudo pkill snort
docker stop goflow2
docker rm goflow2

docker stop ml_detector
docker rm ml_detector
#ps aux | grep snort

