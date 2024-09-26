
import sys
import os

#Sfrom sets import Set
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_forest
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

PRIORITY_value_firewall = 1000
PRIORITY_value_premium = 800

class Controller(EventMixin):
    def __init__(self):

        self.firewall_rules = []
        self.premium_hosts = []
        self.mac_to_port = {}
        
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)
        self.parse_policy_file("policy.in")

    def parse_policy_file(self, filename):
        with open(filename, 'r') as f:
            # contents = f.read().split():
            contents = f.read().splitlines()
            num_rules, num_premium = map(int, contents[0].split())

            # the TCP traffic sent to a certain host on a certain port
            # the TCP traffic originated from a certain host to another host on a certain port.
            #
            # the TCP traffic sent to host h4 (10.0.0.4) on port 4001 
            # the TCP traffic from host h2 (10.0.0.2) to host h5 (10.0.0.5) on port 1000
            # should be blocked.
             
            for i in range(1, num_rules + 1):
                parts = contents[i].split(',')
                if len(parts) == 2:
                    self.firewall_rules.append((parts[0], parts[1]))
                elif len(parts) == 3:
                    self.firewall_rules.append((parts[0], parts[1], parts[2]))
                else:
                    log.error("Invalid Rule Detected")

            for i in range(num_rules + 1, num_rules + num_premium + 1):
                self.premium_hosts.append(contents[i])

    # You can write other functions as you need.    
    def _handle_PacketIn (self, event):    

        #解析收到的数据包
        packet = event.parsed
        ip_pack = packet.find('ipv4')
        tcp_pack = packet.find('tcp')

        src_ip = str(ip_pack.srcip)
        dst_ip = str(ip_pack.dstip)
        outport = self.mac_to_port.get(packet.dst, None)
        
        if src_ip in self.premium_hosts or dst_ip in self.premium_hosts:
            queue_id = 1
        else:
            queue_id = 2
        self.install_enqueue(event, packet, outport, queue_id) #outport
    
        if tcp_pack and ip_pack: 
            src_ip = str(ip_pack.srcip)
            dst_ip = str(ip_pack.dstip)
            d_port = tcp_pack.dstport

            for rule in self.firewall_rules: 
                if len(rule) == 2:
                    if dst_ip == rule[0] and d_port == int(rule[1]):
                        return 
                elif len(rule) == 3:
                    if src_ip == rule[0] and dst_ip == rule[1] and d_port == int(rule[2]):
                        return 
        self.forward(event)

        def install_enqueue(event, packet, outport, q_id):  
            # Add your code here
            msg = of.ofp_flow_mod()  
            msg.match = of.ofp_match.from_packet(packet, event.port)
            # msg.match = of.ofp_match.from_packet(packet)  
            msg.actions.append(of.ofp_action_enqueue(port=outport, queue_id=q_id)) 
            msg.data = event.ofp  
            event.connection.send(msg) 

            
        # Check the packet and decide how to route the packet
        def forward(event):
        
            self.mac_to_port[packet.src] = event.port
            outport = self.mac_to_port.get(packet.dst, None)

            if outport:
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                action = of.ofp_action_output(port=outport)
                msg.actions.append(action)
                event.connection.send(msg)
            else:
                self.flood(event)

        # When it knows nothing about the destination, flood but don't install the rule
        def flood (event):
            # Add your code here
            # define your message here

            # ofp_action_output: forwarding packets out of a physical or virtual port
            # OFPP_FLOOD: output all openflow ports expect the input port and those with 
            #    flooding disabled via the OFPPC_NO_FLOOD port config bit
            # msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))

            # Add an indented block of code here
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            action1 = of.ofp_action_output(port = of.OFPP_FLOOD)
            msg.actions.append(action1)
            event.connection.send(msg)

        # forward()

    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        
        # Send the firewall policies to the switch
        def sendFirewallPolicy(connection, policy):
            # define your message here
            # OFPP_NONE: outputting to nowhere
            # msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
            for rule in self.firewall_rules:
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_proto = 6
                if len(rule) == 2:
                    msg.match.nw_dst = IPAddr(rule[0])
                    msg.match.tp_dst = int(rule[1])
                elif len(rule) == 3:
                    msg.match.nw_src = IPAddr(rule[0])
                    msg.match.nw_dst = IPAddr(rule[1])
                    msg.match.tp_dst = int(rule[2])
                msg.priority = 65535 
                msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
                connection.send(msg)

        # for i in [FIREWALL POLICIES]:
        #     sendFirewallPolicy(event.connection, i)
        sendFirewallPolicy(event.connection, self.firewall_rules)    

def launch():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_forest.launch()

    # Starting the controller module
    core.registerNew(Controller)
