---------------------------------------

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**
This will be worth 10% of the assignment grade.

- What files did you modify (and why)?
  - I edited 3 files in total.
    - sr_router.c
      - core file
      - logic to handle different types fo packets
      - ARP, IP packet modifying
      - managing TTL
      - generate ICMP msg
    - sr_router.h
      - update declaration to match the implementation
    - sr_arpcache.c
      - handle ARP request and reply over time.
      - send ARP or Host based on the attempts and time.
- What helper method did you write (and why)?
  - sr_handle_ip_l1:
    - determines an incoming IP packet
      - for the router itself
      - should be forwarded
  - sr_handle_arp_l1:
    - processing ARP requests and replies
    - responding to requests with the router's MAC address
    - updating the ARP cache from ARP replies
  - forward_ip_l2:
    - Forwards IP packets to the next hop
    - decreases the TTL
    - recalculates the checksum
    - find the next hop's MAC address
  - send_icmp_message_l3:
    - sends ICMP messages
    - different types of ICMP messages
    - change based on the type and code
  - send_icmp_time_exceeded_l3:
    - used when a packet's TTL has expired before destination.
  - send_icmp_net_unreachable_l3:
    - used when the router cannot reach to the destination in its routing table.
- What logic did you implement in each file/method?
  - sr_router.c
    - Start from sr_handlepacket()
      - see if the incoming packets is ARP or IP
      - Handle ARP with sr_handle_arp_l1
        - test if the len meet requirement
        - look up the sr interface
        - check if packet is in interface
          - check if arp request
            - memorize and send arp reply
          - check if arp reply
            - memorize, caches MAC, forward queued packets awaiting this reply
      - Handle IP with sr_handle_ip_l1
        - check for min legth with Eth and IP headers
        - check len received is equal to len total
        - check checksum
        - check if packet is in our INF
          - send echo reply if type=8
          - send 3,3 if TCP/UDP
          - for others, call forward_ip_l2
      - forward_ip_l2
        - decrement TTL of the header
        - recalculate checksum
        - check TTL expiration
        - look the next-hop IP address in the routing table based on the destination IP
        - if found match, check ARP cache for next-hop
        - if not found, queues the packet for transmission upon ARP reply receipt
      - send_icmp_time_exceeded_l3 & send_icmp_net_unreachable_l3
        - allocates memory
        - constructs an ICMP message
        - update ETH and IP header of ICMP
        - set source IP to interface IP
        - calculate checksum and send ICMP
      - send_icmp_message_l3
        - build ICMP based on type and code
        - change length and src based on the type and code
        - decide if it is a echo reply or other types
        - check checksums for IP and ICMP headers
        - send to the corresponding source IP address
  - sr_arpcache.c
    - sr_arpcache_sweepreqs
        - iterates over ARP request in the cache's queue
        - decide to send ARP request or destroy baed on times sent and time slapsed since last request
    - handle_arpreq
        - send ARP is fewer than 5 times
        - send Host unreachable when more than 5 times without response
        - send unreachable packet to all packets waiting.

- What problems or challenges did you encounter?
  - Managing Multiple Functions and Variables: There were too many functions and variables to manage. I used the suffixes l1-3 to indicate importance and layer. This strategy helped me debug more efficiently, so if you don't understand what the l0-3 at the end of a name means, it's related to that.
  - I encountered a problem similar to one discussed on Piazza. Traceroute relies on ICMP Time Exceeded packets, so it's crucial that your ICMP packets have their source IP set to the appropriate interface IP (e.g., 10.0.1.1 in the mentioned example). Correcting this was really helpful!!!
  - Implementing Destination Host Unreachable: Developing the Destination Host Unreachable message was particularly time-consuming. Sometimes, it was "too aggressive," either overshadowing other ICMP messages, failing to handle all packets, or having an incorrect source IP, which made the Destination Host Unreachable message undelivered.
  - Implementing Time to Live Exceeded Message: Implementing the message "From 10.0.1.1 icmp_seq=1 Time to live exceeded" also presented challenges. I had to create a new function specifically for handling this scenario.

***my rtable***

192.168.2.2   192.168.2.2    255.255.255.255    eth1
172.64.3.10   172.64.3.10    255.255.255.255    eth2
10.0.1.100    10.0.1.100     255.255.255.255    eth3
192.64.8.8    192.64.8.8     255.255.255.255    eth1

***The Test***

- Ping from the client to any of the router’s interfaces (192.168.2.1, 172.64.3.1, 10.0.1.1).
- client ping -c 3 192.168.2.1
- client ping -c 3 172.64.3.1
- client ping -c 3 10.0.1.100
- Ping from the client to any of the app servers (192.168.2.2, 172.64.3.10)
  - client ping -c 3 192.168.2.2
  - client ping -c 3 172.64.3.10
- Traceroute from the client to any of the router’s interfaces
  - client traceroute -n 192.168.2.1
  - client traceroute -n 172.64.3.1
  - client traceroute -n 10.0.1.100
- Traceroute from the client to any of the app servers
  - client traceroute -n 192.168.2.2
  - client traceroute -n 172.64.3.10
- Downloading a file using HTTP from one of the app servers
  - client wget <http://192.168.2.2>
  - client wget <http://172.64.3.10>
- Other
  - client ping -c 3 -t 1 192.168.2.2
  - client ping -c 3 10.0.4.4
  - client ping -c 3 192.64.8.8
