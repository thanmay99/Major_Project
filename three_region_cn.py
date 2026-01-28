from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
import time

def topology():
    "Create a network."
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    print("*** Creating nodes")
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6633)
    
    # Create three switches
    s1 = net.addSwitch('s1', mac='00:00:00:00:00:01')
    s2 = net.addSwitch('s2', mac='00:00:00:00:00:02') 
    s3 = net.addSwitch('s3', mac='00:00:00:00:00:03')
    
    # Create hosts - two hosts per switch
    # Switch 1 hosts (192.168.10.0/24)
    h1 = net.addHost('h1', mac='00:00:00:00:00:11', ip='192.168.10.11/24')
    h4 = net.addHost('h4', mac='00:00:00:00:00:14', ip='192.168.10.12/24')
    
    # Switch 2 hosts (192.168.50.0/24)  
    h2 = net.addHost('h2', mac='00:00:00:00:00:22', ip='192.168.50.11/24')
    h5 = net.addHost('h5', mac='00:00:00:00:00:25', ip='192.168.50.12/24')
    
    # Switch 3 hosts (192.168.100.0/24)
    h3 = net.addHost('h3', mac='00:00:00:00:00:33', ip='192.168.100.11/24')
    h6 = net.addHost('h6', mac='00:00:00:00:00:36', ip='192.168.100.12/24')

    print("*** Creating links")
    # Connect hosts to switches
    net.addLink(h1, s1, 0, 1)
    net.addLink(h4, s1, 0, 4)
    net.addLink(h2, s2, 0, 1)
    net.addLink(h5, s2, 0, 4)
    net.addLink(h3, s3, 0, 1)
    net.addLink(h6, s3, 0, 4)
    
    # Connect switches in triangular pattern
    net.addLink(s1, s2, 2, 2)
    net.addLink(s2, s3, 3, 2)  
    net.addLink(s3, s1, 3, 3)

    print("*** Starting network")
    net.build()
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])
    c1.start()

    print("*** Configuring hosts")
    # Configure default gateways and clear ARP
    for host in net.hosts:
        if host.name in ['h1', 'h4']:
            host.cmd('ip route del default 2>/dev/null; ip route add default via 192.168.10.1')
            host.cmd('arp -d 192.168.10.1 2>/dev/null')
        elif host.name in ['h2', 'h5']:
            host.cmd('ip route del default 2>/dev/null; ip route add default via 192.168.50.1')
            host.cmd('arp -d 192.168.50.1 2>/dev/null')
        elif host.name in ['h3', 'h6']:
            host.cmd('ip route del default 2>/dev/null; ip route add default via 192.168.100.1')
            host.cmd('arp -d 192.168.100.1 2>/dev/null')

    print("*** Triggering ARP and host discovery")
    # Ping gateways to trigger ARP and host discovery
    for host in net.hosts:
        if host.name in ['h1', 'h4']:
            host.cmd('ping -c 2 192.168.10.1 >/dev/null 2>&1 &')
        elif host.name in ['h2', 'h5']:
            host.cmd('ping -c 2 192.168.50.1 >/dev/null 2>&1 &')
        elif host.name in ['h3', 'h6']:
            host.cmd('ping -c 2 192.168.100.1 >/dev/null 2>&1 &')
    
    print("*** Waiting for host discovery")
    time.sleep(3)

    print("*** Testing connectivity step by step")
    # Test same subnet
    print("Testing same subnet...")
    print("h1 -> h4:", net.ping([h1, h4]))
    print("h2 -> h5:", net.ping([h2, h5])) 
    print("h3 -> h6:", net.ping([h3, h6]))
    
    # Test cross subnet
    print("Testing cross subnet...")
    print("h1 -> h2:", net.ping([h1, h2]))
    print("h1 -> h3:", net.ping([h1, h3]))

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()