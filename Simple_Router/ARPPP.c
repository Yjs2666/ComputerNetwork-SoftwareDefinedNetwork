/**********************************************************************
 * file:  sr_router.c
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    //is this on purpose?
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  //***************************
  // print_hdrs(packet, len);


  /* fill in code here */

  //***************************
  //handle IP & ARP packets
  sr_ethernet_hdr_t *ehdr_l0 = (sr_ethernet_hdr_t *)packet;  //可以删除?
  uint16_t ethtype_l0 = ethertype(packet);

  if (ethtype_l0 == ethertype_ip) {
    sr_handle_ip_l1(sr, packet, len, interface);
  }
  else if (ethtype_l0 == ethertype_arp) {
    sr_handle_arp_l1(sr, packet, len, interface);
  }
  else {
    fprintf(stderr, "Warning: Not IP Or ARP. Dropping...\n");
  }
  
} /* end sr_handlepacket */

/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h. If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */


// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------

void sr_handle_arp_l1(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "ARP packet does not meet minimum length requirement.\n");
    return;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t arp_op = ntohs(arp_hdr->ar_op);


  printf("------------ It's an ARP Packet ----------------\n");
  print_hdr_eth(packet);
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
  printf("------------------------------------------------\n");
  

  /*
         * For ARP Requests: Send an ARP reply if the target IP address is one of your router’s IP addresses.
         * For ARP Replies: Cache the entry if the target IP address is one of your router’s IP addresses.
         * Check if target IP is one of router's IP addresses.
         * */

  struct sr_if *if_walker = 0;
  if_walker = sr->if_list;
  while (if_walker)
  {
    if (if_walker->ip == arp_hdr->ar_tip) {
      printf("ARP packet is in Interface.\n");
      if (arp_op == arp_op_request) {
        printf("ARP REQUEST received.\n");
        sr_arp_hdr_t *arp_reply = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
        arp_reply->ar_hrd = htons(arp_hrd_ethernet);
        arp_reply->ar_pro = htons(ethertype_ip);
        arp_reply->ar_hln = ETHER_ADDR_LEN;
        arp_reply->ar_pln = sizeof(uint32_t);
        arp_reply->ar_op = htons(arp_op_reply);
        arp_reply->ar_sip = if_walker->ip;
        arp_reply->ar_tip = arp_hdr->ar_sip;
        memcpy(arp_reply->ar_sha, if_walker->addr, ETHER_ADDR_LEN);
        memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
        memcpy(packet + sizeof(sr_ethernet_hdr_t), arp_reply, sizeof(sr_arp_hdr_t));
        sr_send_packet(sr, packet, len, interface);
        free(arp_reply);
        
      }
      else if (arp_op == arp_op_reply) {
        printf("ARP REPLY received.\n");
        struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (req) {
          struct sr_packet *pkt = req->packets;
          while (pkt) {
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt->buf;
            memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, if_walker->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
            pkt = pkt->next;
          }
          sr_arpreq_destroy(&(sr->cache), req);
        }
      }
      return;
    }
    if_walker = if_walker->next;
  }
  fprintf(stderr, "ARP packet is not in interfaces.\n");

}

// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------




void sr_handle_ip_l1(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "Missing Ethernet Hdr Or Ip Hdr\n");
    return;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t ip_total_length = ntohs(ip_hdr->ip_len);
  if (len < ip_total_length + sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "IP packet total_len != recv_len.\n");
    return;
  }

  uint16_t ip_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (new_ip_sum != ip_sum) {
    fprintf(stderr, "IP checksum failed\n");
    return;
  }

//*****************
  printf("----------- It's an IP Packet ------------\n");
  print_hdr_eth(packet);
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
  printf("------------------------------------------\n");


  /* Check if the IP address matches the current router's IP addresses */
  // Check if the packet is for one of our interfaces
  struct sr_if *if_curr = sr_get_interface(sr, interface);
  struct sr_if *if_walker = 0;
  if_walker = sr->if_list;

  while (if_walker){
    if (if_walker->ip == ip_hdr->ip_dst) {
      printf("IP Packet is for one of our interfaces.\n");
      // handle_ip(sr, ip_hdr, if_curr, packet, len);
      if(ip_hdr->ip_p == ip_protocol_icmp){
        ///ICMP CONFIRMED
        // sr_handle_icmp_l1(sr, packet, len, interface);
        if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){
          fprintf(stderr, "ICMP header doesn't meet minimum length.\n");
          return;
        }

         sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          printf("------------ ICMP HDR ------------------\n");
          print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          printf("-----------------------------------------\n");

          /* if it's an ICMP echo request, send echo reply */
          if (icmp_hdr->icmp_type == 8)
          {
          /* Const  uct ICMP echo reply */
            send_icmp_message(sr, packet, if_curr, 0, 0, len);
          }
      }
      else{
        fprintf(stderr, "NOT ICMP\n");
        /* Send ICMP type 3 code 3: Port Unreachable */
        send_icmp_message(sr, packet, if_curr, 3, 3, len);
      }
      return;
    }
    if_walker = if_walker->next;
  }
  //  // If you determine that a datagram should be forwarded, you should correctly decrement the TTL field of the header 
  // and recompute the checksum over the changed header before forwarding it to the next hop.
  forward_ip_l2(sr, ip_hdr, (sr_ethernet_hdr_t *)packet, packet, len, if_curr);
}


// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------
// ---------------------------------------


void forward_ip_l2(struct sr_instance* sr, sr_ip_hdr_t* ip_hdr, sr_ethernet_hdr_t* eth_hdr, uint8_t* packet, unsigned int len, struct sr_if* if_curr) {
    /* 减少TTL */
    ip_hdr->ip_ttl -= 1;

    /* 如果TTL减到0，则发送ICMP Time Exceeded消息 */
    if (ip_hdr->ip_ttl == 0) {
        fprintf(stderr, "Debug: ICMP TIME EXCEED\n");
        send_icmp_message(sr, packet, if_curr, 11, 0, len);
        return;
    }

    /* 重新计算校验和 */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_rt* matched_entry = NULL;
    uint32_t max_mask = 0; // 使用uint32_t类型，与IP地址掩码类型保持一致
    uint32_t dest_ip = ip_hdr->ip_dst;

    struct sr_rt* entry = sr->routing_table;
    while (entry != NULL) {
        uint32_t mask = entry->mask.s_addr;
        uint32_t dest = entry->dest.s_addr;
        if ((dest & mask) == (dest_ip & mask) && mask >= max_mask) {
            matched_entry = entry;
            max_mask = mask;
        }
        entry = entry->next;
    }

    if (!matched_entry) {
        /* 如果没有找到匹配的路由条目，发送ICMP Destination Net Unreachable消息 */
        fprintf(stderr, "Debug: Sending ICMP Destination Net Unreachable\n");
        send_icmp_message(sr, packet, if_curr, 3, 0, len);
        return;
    }

    /* 查找出口接口 */
    struct sr_if* out_if = sr_get_interface(sr, matched_entry->interface);
    if (out_if == NULL) {
        fprintf(stderr, "Outgoing Interface出口接口未找到.\n");
        return;
    }

    /* 查找ARP缓存以获取下一跳MAC地址 */
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), matched_entry->gw.s_addr);
    if (arp_entry) {
        /* 设置以太网头部 */
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
        eth_hdr->ether_type = htons(ethertype_ip);

        /* 发送数据包 */
        fprintf(stderr, "Debug: Sending packet to next hop.\n");
        sr_send_packet(sr, packet, len, out_if->name);
        free(arp_entry);
    } else {
        /* 如果ARP缓存中没有下一跳的MAC地址，将数据包加入到ARP请求队列 */
        fprintf(stderr, "Debug: Queueing packet for ARP request.\n");          
        struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), matched_entry->gw.s_addr, packet, len, out_if->name);
        handle_arpreq(sr, req);
    }
}



void send_icmp_message(struct sr_instance *sr, uint8_t *packet, struct sr_if *inf, uint8_t icmp_type, uint8_t icmp_code, unsigned int len)
{
  uint8_t *icmp_packet;
  unsigned int icmp_packet_len;

  if (icmp_type == 0) {
    icmp_packet_len = len;
  } else {
    icmp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }


  icmp_packet = malloc(icmp_packet_len);
  memcpy(icmp_packet, packet, icmp_packet_len);

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, inf->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));

  /* Choose which interface to send it out on */
  if ((icmp_type == 0 && icmp_code == 0) || (icmp_type == 3 && icmp_code == 3))
  { /* If echo reply or port unreachable, it was meant for a router interface, so use the source destination */
    ip_hdr->ip_src = ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_dst;
  }
  else
  { /* Otherwise, use any ip from the router itself */
    ip_hdr->ip_src = inf->ip;
  }
  ip_hdr->ip_dst = ((sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)))->ip_src;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  if (icmp_type == 3)
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Modify ICMP header */
  if (icmp_type == 0 && icmp_code == 0) /* Echo Reply */
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else
  {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->next_mtu = 0;
    icmp_hdr->unused = 0;
    /* Copy the internet header into the data */
    memcpy(icmp_hdr->data, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
    /* Copy the first 8 bytes of original datagram's data into the data */
    memcpy(icmp_hdr->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  }

  printf("----------- Send ICMP Message ------------\n");
  print_hdr_eth(icmp_packet);
  print_hdr_ip(icmp_packet + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  printf("------------------------------------------\n");

  forward_ip_l2(sr, ip_hdr, eth_hdr, icmp_packet, icmp_packet_len, inf);
  free(icmp_packet);
}
 



