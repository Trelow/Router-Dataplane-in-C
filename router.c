#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAC_LEN 6
#define ARP_CAHCHE_LEN 10
#define RTABLE_LEN 100000

// Node of a binary trie
typedef struct trie_node {
  // Pointer to right (1)
  struct trie_node *right;
  // Pointer to left (0)
  struct trie_node *left;
  // Data
  struct route_table_entry *entry;
} trie_node;

// Structure for a queue element
typedef struct queue_element {
  char buf[MAX_PACKET_LEN];
  struct route_table_entry *entry;
  int len;
} queue_element;

// Function to create a new trie
trie_node *create_trie() {
  trie_node *root = malloc(sizeof(trie_node));
  root->right = NULL;
  root->left = NULL;
  root->entry = NULL;
  return root;
}

// Function to create a new trie node
trie_node *create_trie_node(struct route_table_entry *entry) {
  trie_node *new_node = malloc(sizeof(trie_node));
  new_node->right = NULL;
  new_node->left = NULL;
  new_node->entry = entry;
  return new_node;
}

// Function to insert a node in the trie
void insert_trie(trie_node *root, struct route_table_entry *entry) {
  // Get the mask and prefix
  uint32_t mask = ntohl(entry->mask);
  uint32_t prefix = ntohl(entry->prefix);

  trie_node *curr = root;
  // Iterate through the bits of the prefix, and traverse the trie
  for (int i = 31; i >= 0; i--) {
    // Get the i-th bit of the prefix
    uint32_t bit = (prefix >> i) & 1;
    // If the i-th bit of the mask is 0, we break, and at current node will
    // be inserted our entry
    if (mask << (31 - i) == 0)
      break;

    // If the i-th bit is 0, we go to the left child
    if (bit == 0) {
      // If there is no left child, we create a new one
      if (curr->left == NULL)
        curr->left = create_trie_node(NULL);
      curr = curr->left;
      // Else, we go to the right child
    } else {
      // The same logic as above but for the right child
      if (curr->right == NULL)
        curr->right = create_trie_node(NULL);
      curr = curr->right;
    }
  }
  // At the end, we assign the entry to the current node
  curr->entry = entry;
}

// Function to get the longest prefix that matches the given ip
struct route_table_entry *get_longest_prefix(trie_node *root, uint32_t ip) {
  trie_node *curr = root;
  struct route_table_entry *longest = NULL;

  // Start traversing the trie till we reach a leaf node
  for (int i = 31; curr != NULL && i >= 0; i--) {
    // Extract the i-th bit of the ip
    uint32_t bit = (ip >> i) & 1;
    // If current node has an entry, we update the longest prefix
    if (curr->entry != NULL)
      longest = curr->entry;
    // If the i-th bit is 0, we go to the left child
    if (bit == 0)
      curr = curr->left;
    // Else, we go to the right child else
    else
      curr = curr->right;
  }
  return longest;
}

// Function to write mac addresses and ethernet type to the header
void write_to_ethernet_header(struct ether_header *eth_hdr, uint8_t *dhost,
                              uint8_t *shost, uint16_t type) {
  memcpy(eth_hdr->ether_dhost, dhost, MAC_LEN);
  memcpy(eth_hdr->ether_shost, shost, MAC_LEN);
  eth_hdr->ether_type = htons(type);
}

// Function to find an entry in the ARP cache
struct arp_table_entry *find_mac(uint32_t ip, struct arp_table_entry *arp_cache,
                                 int cache_len) {
  for (int i = 0; i < cache_len; i++)
    if (arp_cache[i].ip == ip)
      return &arp_cache[i];
  return NULL;
}

// Function to write data to the ARP header
void write_to_arp_header(struct arp_header *arp_hdr, uint16_t op, uint8_t *sha,
                         uint32_t spa, uint8_t *tha, uint32_t tpa) {
  arp_hdr->htype = htons(1);
  arp_hdr->ptype = htons(ETHERTYPE_IP);
  arp_hdr->hlen = 6;
  arp_hdr->plen = 4;
  arp_hdr->op = htons(op);
  memcpy(arp_hdr->tha, tha, 6);
  arp_hdr->tpa = tpa;
  memcpy(arp_hdr->sha, sha, 6);
  arp_hdr->spa = spa;
}

// Function to generate an ARP request
void generate_arp_request(uint32_t ip, int interface) {
  char buf[MAX_PACKET_LEN];
  struct arp_header *arp_hdr =
      (struct arp_header *)(buf + sizeof(struct ether_header));

  // Write data to ethernet header
  uint8_t broadcast_mac[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint8_t interface_mac[MAC_LEN];
  get_interface_mac(interface, interface_mac);
  write_to_ethernet_header((struct ether_header *)buf, broadcast_mac,
                           interface_mac, ETHERTYPE_ARP);
  // Write data to ARP header
  write_to_arp_header(arp_hdr, ARP_REQUEST, interface_mac,
                      inet_addr(get_interface_ip(interface)), broadcast_mac,
                      ip);
  // Send the request
  send_to_link(interface, buf,
               sizeof(struct ether_header) + sizeof(struct arp_header));
}

// Function to send an ARP reply
void send_arp_reply(char *buf, int interface) {
  struct arp_header *arp_hdr =
      (struct arp_header *)(buf + sizeof(struct ether_header));

  // Write data to ethernet header
  uint8_t interface_mac[MAC_LEN];
  get_interface_mac(interface, interface_mac);
  write_to_ethernet_header((struct ether_header *)buf, arp_hdr->sha,
                           interface_mac, ETHERTYPE_ARP);
  // Write data to ARP header
  write_to_arp_header(arp_hdr, ARP_REPLY, interface_mac,
                      inet_addr(get_interface_ip(interface)), arp_hdr->sha,
                      arp_hdr->spa);
  // Send the reply
  send_to_link(interface, buf,
               sizeof(struct ether_header) + sizeof(struct arp_header));
}

// Function to send an ICMP packet
void send_icmp(char *buf, int interface, int type) {
  // Extract headers
  struct ether_header *eth_hdr = (struct ether_header *)buf;
  struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
  struct icmphdr *icmp_hdr =
      (struct icmphdr *)(buf + sizeof(struct ether_header) +
                         sizeof(struct iphdr));
  // Write data to ethernet header
  uint8_t interface_mac[MAC_LEN];
  get_interface_mac(interface, interface_mac);
  write_to_ethernet_header(eth_hdr, eth_hdr->ether_shost, interface_mac,
                           ETHERTYPE_IP);
  // Set protocol type and update total length
  ip_hdr->protocol = IPPROTO_ICMP;
  ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
  // Swap source and destination IP, and set TTL
  ip_hdr->daddr = ip_hdr->saddr;
  ip_hdr->saddr = inet_addr(get_interface_ip(interface));
  ip_hdr->ttl = 64;
  // Checksum
  ip_hdr->check = 0;
  ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

  // Set ICMP type, code and checksum
  icmp_hdr->type = type;
  icmp_hdr->code = 0;
  icmp_hdr->checksum = 0;
  icmp_hdr->checksum =
      htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));
  // Send ICMP packet
  send_to_link(interface, buf,
               sizeof(struct ether_header) + sizeof(struct iphdr) +
                   sizeof(struct icmphdr));
}

int main(int argc, char *argv[]) {
  char buf[MAX_PACKET_LEN];
  // Do not modify this line
  init(argc - 2, argv + 2);

  // Read routing table
  struct route_table_entry *rtable;
  rtable = malloc(sizeof(struct route_table_entry) * RTABLE_LEN);
  int rtable_len = read_rtable(argv[1], rtable);

  // Create a trie based on the routing table
  trie_node *root = create_trie();
  for (int i = 0; i < rtable_len; i++)
    insert_trie(root, &rtable[i]);

  // Declare ARP cache and queue
  struct arp_table_entry arp_cache[ARP_CAHCHE_LEN];
  int arp_cache_len = 0;
  // Create queue
  queue q = queue_create();
  int queue_size = 0;

  while (1) {
    int interface;
    size_t len;

    interface = recv_from_any_link(buf, &len);
    DIE(interface < 0, "recv_from_any_links");

    struct ether_header *eth_hdr = (struct ether_header *)buf;
    /* Note that packets received are in network order,
    any header field which has more than 1 byte will need to be conerted to
    host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed
    when sending a packet on the link, */

    // If the packet is shorter than the minimum length, drop it
    if (len < sizeof(struct ether_header))
      continue;

    // Check if MAC address is router address or broadcast
    uint8_t broadcast_mac[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t interface_mac[MAC_LEN];
    get_interface_mac(interface, interface_mac);
    if (memcmp(eth_hdr->ether_dhost, interface_mac, MAC_LEN) != 0 &&
        memcmp(eth_hdr->ether_dhost, broadcast_mac, MAC_LEN) != 0)
      continue;

    // If e received an Ipv4 packet
    if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
      // Parse the IP header
      struct iphdr *ip_hdr =
          (struct iphdr *)(buf + sizeof(struct ether_header));

      // Check the checksum
      if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0)
        continue;

      // If the packet is for the router, reply with an ICMP packet
      if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
        struct icmphdr *icmp_hdr =
            (struct icmphdr *)(buf + sizeof(struct ether_header) +
                               sizeof(struct iphdr));
        if (icmp_hdr->type == 8 && icmp_hdr->code == 0)
          send_icmp(buf, interface, 0);
        continue;
      }

      // Check ttl
      if (ip_hdr->ttl <= 1) {
        send_icmp(buf, interface, 11);
        continue;
      }

      // Get the longest prefix that matches the destination IP
      struct route_table_entry *longest_prefix =
          get_longest_prefix(root, ntohl(ip_hdr->daddr));
      // If no prefix matches, send an ICMP packet
      if (longest_prefix == NULL) {
        send_icmp(buf, interface, 3);
        continue;
      }

      // Update the TTL and checksum
      uint16_t prev_checksum = ip_hdr->check;
      uint16_t prev_ttl = ip_hdr->ttl;
      ip_hdr->ttl--;
      // Recalculate the checksum
      uint16_t new_checksum =
          ~(~prev_checksum + ~((uint16_t)prev_ttl) + (uint16_t)ip_hdr->ttl) - 1;
      ip_hdr->check = new_checksum;

      // Find the MAC address of the next hop
      struct arp_table_entry *mac_en =
          find_mac(longest_prefix->next_hop, arp_cache, arp_cache_len);
      // If the MAC address is not in the cache, send an ARP request
      if (mac_en == NULL) {
        generate_arp_request(longest_prefix->next_hop,
                             longest_prefix->interface);
        // Add current packet to the queue
        queue_element *data = malloc(sizeof(queue_element));
        memcpy(data->buf, buf, len);
        data->entry = longest_prefix;
        data->len = len;
        get_interface_mac(longest_prefix->interface,
                          (uint8_t *)eth_hdr->ether_shost);
        queue_enq(q, data);
        queue_size++;
        // Else, copy the MAC address and send the packet
      } else {
        memcpy(eth_hdr->ether_dhost, mac_en->mac, MAC_LEN);
        send_to_link(longest_prefix->interface, buf, len);
      }
      // If we received an ARP packet
    } else if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP)) {
      // Parse the ARP header
      struct arp_header *arp_hdr =
          (struct arp_header *)(buf + sizeof(struct ether_header));
      // If the packet is an ARP reply
      if (ntohs(arp_hdr->op) == ARP_REPLY) {
        // Add the MAC address to the cache
        arp_cache[arp_cache_len].ip = arp_hdr->spa;
        memcpy(arp_cache[arp_cache_len].mac, arp_hdr->sha, MAC_LEN);
        arp_cache_len++;

        // Send packets from the queue whose next hop mac we now know
        for (int i = 0; i < queue_size; i++) {
          // Dequeue the packet
          queue_element *data = queue_deq(q);
          struct route_table_entry *entry = data->entry;
          struct ether_header *eth_hdr = (struct ether_header *)data->buf;
          // Find the MAC address of the next hop
          struct arp_table_entry *mac_en =
              find_mac(entry->next_hop, arp_cache, arp_cache_len);
          // If the MAC was found, send the packet
          if (mac_en != NULL) {
            memcpy(eth_hdr->ether_dhost, mac_en->mac, MAC_LEN);
            send_to_link(entry->interface, data->buf, data->len);
            free(data);
            queue_size--;
            // Else, add the packet back to the queue
          } else
            queue_enq(q, data);
        }
        // If the packet is an ARP request, send an ARP reply
      } else if (ntohs(arp_hdr->op) == ARP_REQUEST) {
        // Check if the request is for the router
        if (arp_hdr->tpa == inet_addr(get_interface_ip(interface)))
          send_arp_reply(buf, interface);
      }
    }
  }
}
