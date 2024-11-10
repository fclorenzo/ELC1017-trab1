from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class BasicTopo(Topo):
    "A LinuxRouter connecting two hosts with valid IP configurations"

    def build(self, **_opts):
        # Define the router (without a single IP as it will have IPs per interface)
        router = self.addHost('r', ip=None)

        # Define hosts with specific IPs and default routes through the router
        host1 = self.addHost('h1', ip='20.1.1.1/24', defaultRoute='via 10.1.1.254')
        host2 = self.addHost('h2', ip='20.1.1.2/24', defaultRoute='via 10.2.2.254')

        # Connect host1 to router with specific IPs for each interface
        self.addLink(host1, router, 
             intfName1='h1-eth0', params1={'ip':'20.1.1.1/24'},
             intfName2='r-eth1', params2={'ip':'10.1.1.254/24'})

        # Connect host2 to router with specific IPs for each interface
        self.addLink(host2, router, 
             intfName1='h2-eth0', params1={'ip':'20.1.1.2/24'},
             intfName2='r-eth2', params2={'ip':'10.2.2.254/24'})

def run():
    "Set up and run the network with CLI"
    net = Mininet(topo=BasicTopo(), controller=None)
    
    # Disable hardware offloading for packet manipulation
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K '+itf.name+' tx off rx off')
    
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
