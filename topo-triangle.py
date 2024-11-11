from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class MultiRouterTopo(Topo):
    "A topology with three interconnected routers and one host per router."

    def build(self, **_opts):
        # Define routers
        r1 = self.addHost("r1", ip=None)
        r2 = self.addHost("r2", ip=None)
        r3 = self.addHost("r3", ip=None)

        # Define hosts connected to each router
        h1 = self.addHost("h1", ip="10.1.1.1/24", defaultRoute="via 10.1.1.254")
        h2 = self.addHost("h2", ip="10.2.2.1/24", defaultRoute="via 10.2.2.254")
        h3 = self.addHost("h3", ip="10.3.3.1/24", defaultRoute="via 10.3.3.254")

        # Links between each host and its router
        self.addLink(h1, r1, intfName1="h1-eth0", params1={"ip": "10.1.1.1/24"},
                     intfName2="r1-eth0", params2={"ip": "10.1.1.254/24"})
        
        self.addLink(h2, r2, intfName1="h2-eth0", params1={"ip": "10.2.2.1/24"},
                     intfName2="r2-eth0", params2={"ip": "10.2.2.254/24"})

        self.addLink(h3, r3, intfName1="h3-eth0", params1={"ip": "10.3.3.1/24"},
                     intfName2="r3-eth0", params2={"ip": "10.3.3.254/24"})

        # Links between routers (forming a triangle topology)
        self.addLink(r1, r2, intfName1="r1-eth1", params1={"ip": "10.1.2.1/24"},
                     intfName2="r2-eth1", params2={"ip": "10.1.2.2/24"})

        self.addLink(r2, r3, intfName1="r2-eth2", params1={"ip": "10.2.3.1/24"},
                     intfName2="r3-eth1", params2={"ip": "10.2.3.2/24"})

        self.addLink(r3, r1, intfName1="r3-eth2", params1={"ip": "10.3.1.1/24"},
                     intfName2="r1-eth2", params2={"ip": "10.3.1.2/24"})

def run():
    "Set up and run the network with CLI."
    net = Mininet(topo=MultiRouterTopo(), controller=None)

    # Disable hardware offloading for packet manipulation
    for _, v in net.nameToNode.items():
        for intf in v.intfList():
            v.cmd("ethtool -K " + intf.name + " tx off rx off")

    # Enable IP forwarding on all routers
    for router_name in ['r1', 'r2', 'r3']:
        router = net.get(router_name)
        router.cmd("sysctl -w net.ipv4.ip_forward=1")

    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    run()
