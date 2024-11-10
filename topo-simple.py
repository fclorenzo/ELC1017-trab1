from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class SingleIPRouterTopo(Topo):
    "A topology with a router having a single IP address on its loopback interface."

    def build(self, **_opts):
        # Define the router and assign a single IP on loopback
        router = self.addHost('r', ip='10.0.0.1/24')  # Single IP for the router

        # Define hosts with specific IPs and default routes through the router's loopback IP
        host1 = self.addHost('h1', ip='20.1.1.1/24', defaultRoute='via 10.0.0.1')
        host2 = self.addHost('h2', ip='20.2.2.1/24', defaultRoute='via 10.0.0.1')

        # Connect hosts to the router
        self.addLink(host1, router, intfName1='h1-eth0', params1={'ip': '20.1.1.1/24'})
        self.addLink(host2, router, intfName2='h2-eth0', params1={'ip': '20.2.2.1/24'})

def run():
    "Set up and run the network with CLI"
    net = Mininet(topo=SingleIPRouterTopo(), controller=None)

    # Disable hardware offloading for packet manipulation
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K '+itf.name+' tx off rx off')

    # Set router loopback IP manually
    router = net.get('r')
    router.cmd("ifconfig lo 10.0.0.1/32")

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
