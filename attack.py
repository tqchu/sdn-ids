import sys
import signal
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.cli import CLI

class NetworkTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        hosts = []
        for i in range(1, 10):
            h = self.addHost(f"h{i}", ip=f"198.51.100.{10 + i}/24", defaultRoute=None)
            self.addLink(h, s1)
            hosts.append(h)
        self.my_hosts = hosts

def main():
    setLogLevel('info')
    topo = NetworkTopo()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip="127.0.0.1", port=6633)
    )
    net.start()

    # Attach veth-mn to s1
    s1 = net.get('s1')
    s1.attach('veth-mininet')
    print("[*] Attached veth-mn to s1 for integration with the real/VM network via OVS bridge.")

    # Optionally up interfaces (should be up already)
    for i in range(1, 10):
        net[f"h{i}"].cmd("ip link set dev h{}-eth0 up".format(i))

    # Attack logic
    if len(sys.argv) == 2:
        print("[*] Attack mode: All hosts except victim will attack")
        processes = []

        for i in range(1, 10):
            host = net[f"h{i}"]
            cmd = sys.argv[1]
            print(f"[+] {host.name} running: {cmd}")
            pid_output = host.cmd(f"{cmd} & echo $!")
            pid_str = pid_output.strip().splitlines()[-1]
            try:
                pid = int(pid_str)
            except ValueError:
                print(f"Failed to get PID from output: {pid_output}")
                continue
            processes.append((host, pid))

        def stop_attack(signum, frame):
            print("\n[!] Stopping attack and cleaning up...")
            for host, pid in processes:
                host.cmd(f'kill -9 {pid}')
            net.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, stop_attack)
        print("[*] Attack running. Press Ctrl+C to stop.")
        signal.pause()
    else:
        print("[*] Custom 5-host flat topology ready, starting Mininet CLI...")
        CLI(net)
        net.stop()

if __name__ == '__main__':
    main()
