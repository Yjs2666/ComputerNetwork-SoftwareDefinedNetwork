from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections,irange
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')

        c1 = self.addSwitch('c1')
        a1 = self.addSwitch('a1')
        a2 = self.addSwitch('a2')
        e1 = self.addSwitch('e1')
        e2 = self.addSwitch('e2')
        e3 = self.addSwitch('e3')
        e4 = self.addSwitch('e4')
        
        # Add links
        self.addLink(c1, a1)
        self.addLink(c1, a2)
        self.addLink(a1, e1)
        self.addLink(a1, e2)
        self.addLink(a2, e3)
        self.addLink(a2, e4)
        self.addLink(e1, h1)
        self.addLink(e1, h2)
        self.addLink(e2, h3)
        self.addLink(e2, h4)
        self.addLink(e3, h5)
        self.addLink(e3, h6)
        self.addLink(e4, h7)
        self.addLink(e4, h8)

# topo = { 'mytopo': ( lambda: MyTopo() ) }
        
def runExperiment():
    topo = MyTopo()
    net = Mininet( topo=topo, link=TCLink )
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    runExperiment()

