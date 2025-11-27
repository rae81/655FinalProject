#!/usr/bin/env python3
"""
topology.py - Minimal LLDP IDS testbed for SDN controller testing

Purpose: Create 2-switch topology for LLDP discovery and attack simulation
Architecture: h1 (attacker) --- s1 --- s2 --- h2 (victim)

References:
- github.com/mininet/mininet (basic topology creation and CLI)
- github.com/mininet/mininet/blob/master/examples/controllers.py (RemoteController usage)
- mininet.org/walkthrough (network setup and configuration)
- github.com/faucetsdn/ryu/tree/master/ryu/topology (OpenFlow13 protocol requirement)

by  Rami Eid
"""

# From: github.com/mininet/mininet
# Purpose: Core Mininet classes for network emulation
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def create_testbed():
    """
    Create minimal SDN testbed with 2 switches and 2 hosts
    
    Topology:
        h1 (10.0.0.1) --- s1 --- s2 --- h2 (10.0.0.2)
                           |       |
                           LLDP flows between switches
    """
    
    # From: mininet.org/api/classmininet_1_1net_1_1Mininet.html
    # Purpose: Initialize Mininet network with remote controller and OVS switches
    info('*** Creating network\n')
    net = Mininet(
        controller=RemoteController,  # Expects external controller (Ryu)
        switch=OVSSwitch,              # Use Open vSwitch implementation
        autoSetMacs=True,              # Simplify MAC addresses (00:00:00:00:00:01, etc)
        autoStaticArp=True             # Pre-populate ARP tables to reduce overhead
    )
    
    # From: github.com/mininet/mininet/blob/master/examples/controllers.py
    # Purpose: Add remote controller connection (Ryu IDS will listen on 127.0.0.1:6653)
    info('*** Adding controller\n')
    c0 = net.addController(
        'c0', 
        controller=RemoteController, 
        ip='127.0.0.1',  # Localhost - controller runs on same machine
        port=6653        # Default OpenFlow port
    )
    
    # From: mininet.org/api/classmininet_1_1node_1_1OVSSwitch.html
    # Purpose: Create OpenFlow 1.3 switches for LLDP discovery
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    
    # From: mininet.org/api/classmininet_1_1node_1_1Host.html
    # Purpose: Create end hosts with static IPs
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')  # Attacker host
    h2 = net.addHost('h2', ip='10.0.0.2/24')  # Victim host
    
    # From: mininet.org/walkthrough (Link creation section)
    # Purpose: Connect nodes with virtual Ethernet pairs
    info('*** Creating links\n')
    net.addLink(h1, s1)  # h1-eth0 <-> s1-eth1
    net.addLink(s1, s2)  # s1-eth2 <-> s2-eth1 (LLDP discovery link)
    net.addLink(s2, h2)  # s2-eth2 <-> h2-eth0
    
    # From: mininet.org/api/classmininet_1_1net_1_1Mininet.html
    # Purpose: Start network and configure all components
    info('*** Starting network\n')
    net.start()
    
    info('\n*** Topology active: h1 --- s1 --- s2 --- h2\n')
    
    # From: github.com/mininet/mininet/blob/master/mininet/cli.py
    # Purpose: Drop into interactive command-line interface
    CLI(net)
    
    # From: mininet.org/api/classmininet_1_1net_1_1Mininet.html
    # Purpose: Clean shutdown - stops controller, switches, links, hosts
    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    # From: mininet.org/api/mininet_8log_8py.html
    # Purpose: Set logging verbosity (options: debug, info, output, warning, error, critical)
    setLogLevel('info')
    
    create_testbed()
