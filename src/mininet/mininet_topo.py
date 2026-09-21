#!/usr/bin/env python3
"""
mininet_topo.py - 3-Node Routed Topology for Active Warden Testbed
h1 (10.0.1.2/24) ---> h2 (10.0.1.1/24 | 10.0.2.1/24) ---> h3 (10.0.2.2/24)
"""

from mininet.net import Mininet
from mininet.node import Node, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter(Node):
    """Custom Node class enabling IPv4 forwarding (IP Router)."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable kernel-level IPv4 forwarding
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def run_topology():
    net = Mininet(link=TCLink, waitConnected=True)

    info('*** Adding Routers and Hosts\n')
    # Create Router h2
    h2 = net.addHost('h2', cls=LinuxRouter, ip=None)

    # Create Hosts h1 and h3
    h1 = net.addHost('h1', cls=Host, ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
    h3 = net.addHost('h3', cls=Host, ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')

    info('*** Creating Links\n')
    # Link h1 - h2 (Subnet 10.0.1.0/24)
    net.addLink(h1, h2, intfName1='h1-eth0', intfName2='h2-eth0')

    # Link h2 - h3 (Subnet 10.0.2.0/24)
    net.addLink(h2, h3, intfName1='h2-eth1', intfName2='h3-eth0')

    info('*** Starting Network\n')
    net.start()

    info('*** Configuring Router Interfaces\n')
    h2.cmd('ip addr add 10.0.1.1/24 dev h2-eth0')
    h2.cmd('ip addr add 10.0.2.1/24 dev h2-eth1')

    info('*** Network Ready. Testing basic connectivity...\n')
    net.ping([h1, h3])

    info('*** Spawning Interactive Mininet CLI\n')
    CLI(net)

    info('*** Stopping Network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topology()