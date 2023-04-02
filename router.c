#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>

typedef struct ether_header ether_header;
typedef struct iphdr iphdr;
typedef struct icmphdr icmphdr;
typedef struct arp_header arp_header;
typedef struct route_table_entry rtable_entry;
typedef struct arp_entry arp_entry;
#define MAX_RTABLE_LEN 100000

struct queued_pack {
	uint8_t pack[MAX_PACKET_LEN];
	size_t pack_size;
};

rtable_entry *rtable;
int rtable_len = 0;

arp_entry *arp_table;
int arp_table_len = 0;

void afisare(uint32_t addr) {
	printf("%d.%d.%d.%d\n", (addr>>24)&0xff, (addr>>16)&0xff,(addr>>8)&0xff,addr&0xff);
}

iphdr *get_iphdr(ether_header* frame) {
	iphdr *header = NULL;
	if (ntohs(frame->ether_type) == 0x0800) {
		header = (iphdr *)((char*)frame + sizeof(ether_header));
	}
	return header;
}

icmphdr *get_icmphdr(ether_header* frame) {
	icmphdr *header = NULL;
	return header;
}

arp_header *get_arphdr(ether_header* frame) {
	arp_header *header = NULL;
	if (ntohs(frame->ether_type) == 0x0806) {
		header = (arp_header *)((char*)frame + sizeof(ether_header));
	}
	return header;
}

arp_entry generate_arp_entry(uint32_t ip, uint8_t *mac) {
	arp_entry entry;
	entry.ip = htonl(ip);
	memcpy(entry.mac, mac, 6);

	return entry;
}

void generate_eth_header(ether_header* buf, uint16_t eth_type, uint8_t *source, uint8_t *target) {
	for (int i = 0; i < 6; i++) {
		buf->ether_shost[i] = source[i];
		buf->ether_dhost[i] = target[i];
	}
	buf->ether_type = eth_type;
}

void generate_arp_request(arp_header* arp_hdr, uint8_t *sha, uint32_t spa, uint32_t tpa) {
	arp_hdr->hlen = 6;
	arp_hdr->htype = htons(1);
	arp_hdr->op = htons(1);
	arp_hdr->plen = 4;
	arp_hdr->ptype = htons(0x0800);

	memcpy(arp_hdr->sha, sha, 6);
	arp_hdr->spa = htonl(spa);
	memset(arp_hdr->tha, 0x00, 6);
	arp_hdr->tpa = htonl(tpa);
}

void generate_arp_reply(arp_header* arp_hdr, uint8_t *sha, uint8_t *tha, uint32_t spa, uint32_t tpa) {
	arp_hdr->hlen = 6;
	arp_hdr->htype = htons(1);
	arp_hdr->op = htons(2);
	arp_hdr->plen = 4;
	arp_hdr->ptype = htons(0x0800);

	memcpy(arp_hdr->sha, sha, 6);
	arp_hdr->spa = htonl(spa);
	memcpy(arp_hdr->tha, tha, 6);
	arp_hdr->tpa = htonl(tpa);
}

// Liniar LPM, needs to be improved
rtable_entry *get_best_route(uint32_t ip_dest) {
	rtable_entry *next = NULL;
	uint32_t best = 0;
	for (int i = 0; i < rtable_len; i++) {
			if ((ntohl(rtable[i].mask) & ip_dest) == 
			ntohl(rtable[i].prefix) && best < ntohl(rtable[i].mask)) {
				next = &(rtable[i]);
				best = ntohl(rtable[i].mask);
		}
	}
	
	return next;
}

arp_entry *get_arp_entry(uint32_t ip_dest) {
	for (int i = 0; i < arp_table_len; i++) {
		if (ntohl((uint32_t)arp_table[i].ip) == ip_dest)
			return &(arp_table[i]);
	}
	return NULL;
}

uint32_t ip_to_uint32(char* ip_address) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_address, &addr);
    return ntohl(addr.s_addr);
}

int main(int argc, char *argv[]) {
	rtable = malloc(sizeof(rtable_entry) * MAX_RTABLE_LEN);
	DIE(rtable == NULL, "rtable memory");

	arp_table = malloc(sizeof(arp_entry) * MAX_RTABLE_LEN);
	DIE(arp_table == NULL, "arptable memory");

	rtable_len = read_rtable(argv[1], rtable);
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	queue arp_queue = queue_create();

	int interface;
	char buf[MAX_PACKET_LEN];
	size_t len;

	// Do not modify this line
	init(argc - 2, argv + 2);
	
	
	while (1) {
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		ether_header *eth_hdr = (ether_header *) buf;
		iphdr *ip_hdr = get_iphdr(eth_hdr);
		icmphdr *icmp_hdr = get_icmphdr(eth_hdr);
		arp_header *arp_hdr = get_arphdr(eth_hdr);

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

    	uint8_t  interface_mac[6]; // adresa mac a interfetei
		get_interface_mac(interface, interface_mac);
		uint8_t correct_destination = 1;
		for (int i = 0; i < 6; i++) {
			if (interface_mac[i] != eth_hdr->ether_dhost[i]) {
				correct_destination = 0;
				break;
			}
		}

		uint8_t broadcast_check = 1; 
		for (int i = 0; i < 6; i++) {
			if (0 == eth_hdr->ether_dhost[i]) {
				broadcast_check = 0;
				break;
			}
		}
		if (broadcast_check == 1)
			correct_destination = 1;

		// Check for correct MAC address destination
		if (correct_destination == 0) {
			printf("--Invalid MAC Destination--\n");
			continue;
		}
		
		// IPv4 payload
		if (ip_hdr != NULL) {
			printf("IPv4 implementation\n");
			uint16_t local_checksum = 0;
			uint16_t pack_checksum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			local_checksum = checksum((uint16_t*)ip_hdr, sizeof(iphdr));
			// Check for correct checksum
			if (local_checksum != pack_checksum) {
				printf("--Invalid IPv4 Checksum--\n");
				printf("--local: %X--\n", local_checksum);
				printf("--pack: %X--\n", pack_checksum);
				continue;
			}
			printf("check\n");
			uint8_t old_ttl = ip_hdr->ttl;
			// Check for valid TTL
			if (old_ttl < 2) {
				printf("--No TTL--\n");
				// TODO: Implementare mesaj ICMP "Time Exceeded"
				continue;
			}
			// Updated TTL
			ip_hdr->ttl--;
			printf("ttl\n");
			// Check for next route
			rtable_entry *next_route = get_best_route(ntohl(ip_hdr->daddr));
			if (next_route == NULL) {
				printf("--Next Route Not Found--\n");
				// TODO: Implementare mesaj ICMP "Destination unreachable"
				continue;
			}
			printf("route\n");
			// Updated checksum
			ip_hdr->check = 0;
			uint16_t new_checksum = checksum((uint16_t*)ip_hdr, sizeof(iphdr));
			ip_hdr->check = htons(new_checksum);
			// Updated source and destination mac in ETH header
			arp_entry* next_arp = get_arp_entry(ntohl(next_route->next_hop));
			printf("newcheck\n");
			// ARP Table returned NULL, queue packet and generate ARP
			if (next_arp == NULL) {
				printf("entered arp reqgen\n");
				struct queued_pack *packet = calloc(1, sizeof(struct queued_pack));
				memcpy(packet->pack, buf, MAX_PACKET_LEN);
				packet->pack_size = len;
				queue_enq(arp_queue, packet);

				uint32_t tpa = ntohl(next_route->next_hop);
				// Generated a new packet for ARP request
				memset(buf, 0x00, MAX_PACKET_LEN);
				uint8_t target[6];
				uint8_t source[6];
				memset(target, 0xff, 6);
				get_interface_mac(next_route->interface, source);
				uint32_t spa = ip_to_uint32(get_interface_ip(next_route->interface));

				generate_eth_header(eth_hdr, htons(0x0806), source, target);
				arp_hdr = get_arphdr(eth_hdr);

				generate_arp_request(arp_hdr, source, spa, tpa);
				send_to_link(next_route->interface, buf, sizeof(ether_header) + sizeof(arp_header));

				printf("sent request\n");
				continue;
			}
			printf("found next arp\n");
			
			get_interface_mac(next_route->interface, (eth_hdr->ether_shost));
			memcpy(eth_hdr->ether_dhost, next_arp->mac, 6);
			
			send_to_link(next_route->interface, buf, len);
			printf("IPv4 Implementation ended\n");
			continue;
		}
		
		
		if (arp_hdr != NULL) {
			printf("Got ARP Header\n");
			
			uint16_t op = ntohs(arp_hdr->op);

			// arp op 1 -- Request
			// Request => trimit un reply
			if (op == 1) {
				printf("Got ARP Request\n");
				uint32_t searched_ip = ntohl(arp_hdr->tpa);
				uint32_t local_ip = ip_to_uint32(get_interface_ip(interface));
				// Check if the router is the target ip
				// then build ARP Reply
				if (searched_ip == local_ip) {
					uint8_t l2_target[6];
					uint8_t l2_source[6];
					uint32_t s_ip = ntohl(arp_hdr->spa);
					uint32_t t_ip = ntohl(arp_hdr->tpa);
					uint8_t l3_source[6]; // mac sursa de la care a venit request
					
					//! l3_source cred ca ar putea fi 0x00000
					memcpy(l3_source, arp_hdr->sha, 6);
					memcpy(l2_target, eth_hdr->ether_shost, 6);

					memset(buf, 0x00, MAX_PACKET_LEN);
					get_interface_mac(interface, l2_source);

					generate_eth_header(eth_hdr, htons(0x0806), l2_source, l2_target);
					
					// generate ARP Reply header
					arp_hdr = get_arphdr(eth_hdr);
					/*
					sha - mac interfata curenta, l2_source
					tha - mac pe care a venit, l3_source
					spa - ip interfata curenta, t_ip
					tpa - ip pe care a venit, s_ip
					*/
					generate_arp_reply(arp_hdr, l2_source, l3_source, t_ip, s_ip);
					printf("Sent ARP Reply\n");
					send_to_link(interface, buf, sizeof(ether_header) + sizeof(arp_header));
					continue;
				}
				continue;
			}

			// arp op 2 -- Reply
			// Reply => adaug in cache, trimit pachetul din queue
			if (op == 2) {
				printf("Got ARP Reply\n");
				uint8_t mac_replied[6];
				memcpy(mac_replied, arp_hdr->sha, 6);
				uint32_t ip_replied = ntohl(arp_hdr->spa);
				arp_entry arp_reply = generate_arp_entry(ip_replied, mac_replied);

				// Check if the ARP entry already is in the cache
				int found = 0;
				for(int i = 0; i < arp_table_len; i++) {
					int same_mac = memcmp(arp_table[i].mac, arp_reply.mac, 6);
					if (arp_table[i].ip == arp_reply.ip && same_mac == 0) {
						found = 1;
						break;
					}
				}
				if (found == 1) {
					printf("arp entry already exits\n");
					if (queue_empty(arp_queue) == 0) {
						printf("pack queue not empty\n");
						exit(11);
					}

				}
				if (found == 0) {
					// ARP reply added to cache
					arp_table[arp_table_len++] = arp_reply;
					memset(buf, 0x00, MAX_PACKET_LEN);
					struct queued_pack *queued_pack = queue_deq(arp_queue);
					memcpy(buf, queued_pack->pack, queued_pack->pack_size);
					ip_hdr = get_iphdr(eth_hdr);

					rtable_entry *next_route = get_best_route(ntohl(ip_hdr->daddr));
					if (next_route == NULL) {
						printf("--Next Route Not Found--\n");
						// TODO: Implementare mesaj ICMP "Destination unreachable"
						continue;
					}

					uint8_t source_mac[6];
					get_interface_mac(next_route->interface, source_mac);
					memcpy(eth_hdr->ether_shost, source_mac, 6);
					memcpy(eth_hdr->ether_dhost, arp_reply.mac, 6);

					printf("Sent Pack after Reply\n");
					send_to_link(next_route->interface, buf, queued_pack->pack_size);
				}
			}
			printf("ARP implementation ended\n");
			continue;
		}

		if (icmp_hdr != NULL) {
			printf("ICMP implementation ended\n");
			continue;
		}

		printf("--Router loop ends here--\n");
		continue;
	}
}

