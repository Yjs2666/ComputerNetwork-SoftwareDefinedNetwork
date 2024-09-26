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
    /* 减少TTL, 并重新计算IP头部的校验和 */
    ip_hdr->ip_ttl--;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* 如果TTL减到0，则发送ICMP Time Exceeded消息 */
    // if (ip_hdr->ip_ttl == 0) {
    //     fprintf(stderr, "Debug: ICMP TIME EXCEED\n");
    //     send_icmp_message(sr, packet, if_curr, 11, 0, len);
    //     return;
    // }

    if (ip_hdr->ip_ttl == 0) {
        send_icmp_time_exceeded(sr, packet, eth_hdr, len, if_curr);
        return;
    }

    /* 查找路由表中匹配的项 */
    struct sr_rt* matching_entry = NULL;
    uint32_t longest_match = 0; // 用于记录最长匹配掩码
    struct sr_rt* rt_walker = sr->routing_table;
    while (rt_walker != NULL) {
        if ((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == (ip_hdr->ip_dst & rt_walker->mask.s_addr)) {
            if (rt_walker->mask.s_addr > longest_match) {
                longest_match = rt_walker->mask.s_addr;
                matching_entry = rt_walker;
            }
        }
        rt_walker = rt_walker->next;
    }

    if (!matching_entry) {
        send_icmp_net_unreachable(sr, packet, eth_hdr, len, if_curr);
        return;
    }


    /* 查找ARP缓存以获取下一跳的MAC地址 */
    struct sr_arpentry* cached_arp_entry = sr_arpcache_lookup(&sr->cache, matching_entry->gw.s_addr);
    if (cached_arp_entry) {
        memcpy(eth_hdr->ether_dhost, cached_arp_entry->mac, ETHER_ADDR_LEN);
        struct sr_if* out_interface = sr_get_interface(sr, matching_entry->interface);
        memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, matching_entry->interface);
        free(cached_arp_entry);
    } else {
        /* 如果ARP缓存中没有条目，则需要发送ARP请求 */
        sr_arpcache_queuereq(&sr->cache, matching_entry->gw.s_addr, packet, len, matching_entry->interface);
    }

}



void send_icmp_time_exceeded(struct sr_instance* sr, uint8_t* packet, sr_ethernet_hdr_t* eth_hdr, unsigned int len, struct sr_if* if_curr) 
{
    /* 分配内存并初始化ICMP Time Exceeded消息 */
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
    memset(icmp_packet, 0, icmp_len);

    /* 构造以太网头 */
    sr_ethernet_hdr_t *icmp_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    memcpy(icmp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(icmp_eth_hdr->ether_shost, if_curr->addr, ETHER_ADDR_LEN);
    icmp_eth_hdr->ether_type = htons(ethertype_ip);

    /* 构造IP头 */
    sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    icmp_ip_hdr->ip_hl = 5;
    icmp_ip_hdr->ip_v = 4;
    icmp_ip_hdr->ip_tos = 0;
    icmp_ip_hdr->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
    icmp_ip_hdr->ip_id = 0;
    icmp_ip_hdr->ip_off = htons(IP_DF);
    icmp_ip_hdr->ip_ttl = INIT_TTL;
    icmp_ip_hdr->ip_p = ip_protocol_icmp;
    icmp_ip_hdr->ip_sum = 0;
    icmp_ip_hdr->ip_src = if_curr->ip;
    icmp_ip_hdr->ip_dst = received_ip_hdr->ip_src;
    icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

    /* 构造ICMP Time Exceeded消息 */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 11; // Time Exceeded
    icmp_hdr->icmp_code = 0; // Time to live exceeded in transit
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, received_ip_hdr, ICMP_DATA_SIZE); // 包括IP头和IP数据的前8字节
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    /* 发送ICMP消息 */
    sr_send_packet(sr, icmp_packet, icmp_len, if_curr->name);
    free(icmp_packet);
}

void send_icmp_net_unreachable(struct sr_instance* sr, uint8_t* packet, sr_ethernet_hdr_t* eth_hdr, unsigned int len, struct sr_if* if_curr) 
{
    /* 在这里实现发送ICMP网络不可达消息的逻辑 */
    /* 记得更新源和目的MAC地址，更新IP源地址为当前接口的IP */
    /* 分配内存并初始化ICMP Time Exceeded消息 */
    unsigned int icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);
    memset(icmp_packet, 0, icmp_len);

    /* 构造以太网头 */
    sr_ethernet_hdr_t *icmp_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    memcpy(icmp_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(icmp_eth_hdr->ether_shost, if_curr->addr, ETHER_ADDR_LEN);
    icmp_eth_hdr->ether_type = htons(ethertype_ip);

    /* 构造IP头 */
    sr_ip_hdr_t *icmp_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    icmp_ip_hdr->ip_hl = 5;
    icmp_ip_hdr->ip_v = 4;
    icmp_ip_hdr->ip_tos = 0;
    icmp_ip_hdr->ip_len = htons(icmp_len - sizeof(sr_ethernet_hdr_t));
    icmp_ip_hdr->ip_id = 0;
    icmp_ip_hdr->ip_off = htons(IP_DF);
    icmp_ip_hdr->ip_ttl = INIT_TTL;
    icmp_ip_hdr->ip_p = ip_protocol_icmp;
    icmp_ip_hdr->ip_sum = 0;
    icmp_ip_hdr->ip_src = if_curr->ip;
    icmp_ip_hdr->ip_dst = received_ip_hdr->ip_src;
    icmp_ip_hdr->ip_sum = cksum(icmp_ip_hdr, sizeof(sr_ip_hdr_t));

    /* 构造ICMP Time Exceeded消息 */
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = 3; // Destination Unreachable
    icmp_hdr->icmp_code = 0; // Network Unreachable
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, received_ip_hdr, ICMP_DATA_SIZE); // 包括IP头和IP数据的前8字节
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    /* 发送ICMP消息 */
    sr_send_packet(sr, icmp_packet, icmp_len, if_curr->name);
    free(icmp_packet);
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
  else if(icmp_type == 11)
  { /* If time exceeded, use the router's ip */
    ip_hdr->ip_src = inf->ip;
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

 
