# Router Dataplane in C

This project implements the **dataplane** of a router, handling packet parsing, routing decisions, ARP (Address Resolution Protocol) processing, and ICMP error messaging in **C**. Below is an overview of the main functionalities and design.

---

## Table of Contents
1. [Overview](#overview)  
2. [Routing Process](#routing-process)  
3. [Longest Prefix Match (Binary Trie)](#longest-prefix-match-binary-trie)  
4. [ARP Handling](#arp-handling)  
5. [ICMP Handling](#icmp-handling)  

---

## Overview
The dataplane code manages all **packets** received by the router. Each incoming packet is checked, parsed, and then forwarded or replied to, based on routing table lookups, ARP entries, and ICMP rules.

**Key Points:**
- Written in **C**.
- Uses **Ethernet**, **IPv4**, **ARP**, and **ICMP** protocols.
- Employs a **binary trie** structure for efficient longest prefix matching in the routing table.
- Maintains an **ARP cache** to resolve MAC addresses of next-hop gateways.
- Sends **ICMP error** messages if routes are missing or TTL has expired.

---

## Routing Process
1. **Packet Parsing**  
   - On receiving a packet, we verify that it is not malformed.  
   - We compare the **destination MAC** to the router’s MAC address. If they match, or if it’s a broadcast MAC, the packet is intended for the router.  
   - We then inspect the **EtherType** to determine if the packet is **IPv4** or **ARP**.

2. **IPv4 Handling**  
   - **Parse** the IPv4 header and **verify** its checksum.  
   - **Check the TTL**. If `ttl <= 1`, the packet is dropped, and we may send an ICMP Time Exceeded message. Otherwise, decrement the TTL and recalculate the checksum.  
   - Look up the **best route** using our routing table. If no route exists, send an ICMP Destination Unreachable message.  
   - If a route is found, **locate the MAC address** of the next hop. If it’s not in the ARP cache, **send an ARP request** and enqueue the current packet until the MAC is known.  
   - Once the next hop’s MAC is available, **forward** the packet by updating the Ethernet header and calling `send_to_link`.

---

## Longest Prefix Match (Binary Trie)
- The **routing table** is stored in a **binary trie**, where each node can branch **left (bit=0)** or **right (bit=1)**.  
- Each node may point to a `route_table_entry` or be `NULL` if no route is assigned.  
- During a lookup for the destination IP, we traverse from the most significant bit to the least significant bit:  
  1. Read each bit of the destination IP.  
  2. Move left/right in the trie accordingly.  
  3. Keep track of the **last node** that held a valid `route_table_entry`.  
- The final saved node is the **longest prefix** that matches the IP.

---

## ARP Handling
- **ARP_REQUEST**: When an IP → MAC mapping is unknown, the router sends an ARP request (broadcast) for the **next hop** IP.  
- **ARP_REPLY**: When a reply is received, the **MAC** is **added to the ARP cache**. Any queued packets waiting for this MAC are then dequeued and sent.  
- If the router itself receives an **ARP_REQUEST** for its IP, it constructs and sends an **ARP_REPLY** back.

---

## ICMP Handling
The router handles specific ICMP scenarios:
1. **No Route Found**: Send an **ICMP Destination Unreachable** to the source.  
2. **TTL Expired**: If a packet’s TTL is ≤ 1, send an **ICMP Time Exceeded**.  
3. **Echo Requests (Ping)**: If an IPv4 packet is addressed to the router and contains an **ICMP Echo Request**, reply with an **ICMP Echo Reply** to the source.

---

## Conclusion
By combining **careful packet parsing** with **binary trie lookups** for routing, **ARP caching**, and **ICMP error reporting**, this dataplane provides a core functionality for a simple router. The major protocols—**Ethernet**, **IPv4**, **ARP**, and **ICMP**—are handled in C using raw packet processing functions.

Feel free to explore the code for deeper insights into:
- **Binary trie** insertion and lookup,
- **ARP caching** and timeouts,
- **ICMP** message construction,
- **Checksum** calculation for IP headers.