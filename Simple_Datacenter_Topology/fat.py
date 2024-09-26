from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, OVSSwitch
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.clean import cleanup

"""
Overall:
- k pods - 2 layer, each layer k/2 switches.
- each k-port switch in lower layer, connected to k/2 hosts. 

Core:
- (k/2)^2 switch. 
- each core has one port connected to each of k pods. the ith port of core is connect to pod i such that consecutive ports in the aggregation layer of each pod switch are connected to core switches on (k/2) strides.

Switches:
- k ports
23
01

The ith host connect to ith port of of edge switch.  
"""

class Fat(Topo):
    CoreList = []
    AggrList = []
    EdgeList = []
    HostList = []

    def __init__(self, k):
        super(Fat, self).__init__()
        self.k = k
        self.k2 = k//2
        self.createTopo()

    def createTopo(self):
        self.createCoreLayer()
        self.createAggrLayer()
        self.createEdgeLayer()
        self.createHost()
        self.createLinks()

    def createCoreLayer(self):
        for i in range(1, self.k2 + 1):
            for j in range(1, self.k2 + 1):
                coreS = self.addSwitch((f'cor{i}{j}'),
                        dpid='00:00:00:00:00:{:02d}:{:02d}:{:02d}'.format(self.k, i, j))
                self.CoreList.append(coreS)

    def createAggrLayer(self):
        for pod in range(0, self.k):
            for col in range(0, self.k2):
                aol = col+self.k2
                aggrS = self.addSwitch((f'agg{pod}{aol}'),
                        dpid='00:00:00:00:00:{:02d}:{:02d}:01'.format(pod, aol))
                self.AggrList.append(aggrS)
                edgeS = self.addSwitch((f'edg{pod}{col}'),
                        dpid='00:00:00:00:00:{:02d}:{:02d}:01'.format(pod, col))
                self.EdgeList.append(edgeS)

    def createEdgeLayer(self):
        pass
                
    def createHost(self):
        for pod in range(0, self.k):
            for col in range(0, self.k2):
                for num in range(0, self.k2):
                    hostName = f'h{pod}.{col}.{num+2}'
                    hostIp = f'10.{pod}.{col}.{num}'
                    host = self.addHost(hostName, ip=hostIp)
                    self.HostList.append(host)

    def createLinks(self):
        self.coreToAggr()
        self.aggrToEdge()
        self.edgeToHost()
         
        
    def coreToAggr(self):
        for i in range(0, self.k2):
            for j in range(0, self.k2):
                coreS = self.CoreList[i * (self.k2) + j]
                for l in range(self.k):
                    aggrS = self.AggrList[l * (self.k // 2) + i]
                    self.addLink(coreS, aggrS, port1=l, port2=j+2)
        


    def aggrToEdge(self):  
        for pod in range(0, self.k):
            for col in range(0, self.k2):
                aggrS = self.AggrList[col + pod * self.k2]
                for i in range(0, self.k2):
                    edgeS = self.EdgeList[i + pod * self.k2]
                    self.addLink(aggrS, edgeS,port1=i, port2=col)
        

    def edgeToHost(self): 
        for pod in range(0, self.k):
            for col in range(0, self.k2):
                edgeS = self.EdgeList[col + pod * self.k2]  
                for host in range(0, self.k2):
                    hostH = self.HostList[host + col * self.k2 + pod * self.k]
                    self.addLink(edgeS, hostH, port1=host+2, port2=host+2)


def main():
    cleanup()

    #4 6 8 10
    k = 4 
    topo = Fat(k)
    net = Mininet(topo=topo, switch=OVSSwitch, link=TCLink)
    net.start()
    CLI(net)
    net.stop()
    # OVSS  --  dumpnodeconnections


# if __name__ == '__main__':
#     setLogLevel('info')
#     main()

topos = { 'fatt' : ( lambda : Fat(4)) }

'''    
topos = { 'fatt' : ( lambda : Fat(4)) }

# --controller remote, ip=127.0.0.1, port=6633
# sudo mn --custom fat.py --topo fatt --mac --switch ovsk --controller remote,ip=127.0.0.1,port=6633

# cd pox
# ./pox.py forwarding.hub

# netstat -anp|grep 6633
# kill 3204
'''
