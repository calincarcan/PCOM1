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

void afisare(uint32_t addr);
iphdr *get_iphdr(ether_header* frame);
icmphdr *get_icmphdr(ether_header* frame);
arp_header *get_arphdr(ether_header* frame);
arp_entry generate_arp_entry(uint32_t ip, uint8_t *mac);
void generate_eth_header(ether_header* buf, uint16_t eth_type, uint8_t *source, uint8_t *target);
void generate_arp_request(arp_header* arp_hdr, uint8_t *sha, uint32_t spa, uint32_t tpa);
void generate_arp_reply(arp_header* arp_hdr, uint8_t *sha, uint8_t *tha, uint32_t spa, uint32_t tpa);
void generate_ICMP(ether_header* eth_hdr, iphdr* ip_hdr, icmphdr* icmp_hdr, int interface, uint8_t type);
void generate_ICMP_REPLY(ether_header* eth_hdr, iphdr* ip_hdr, icmphdr* icmp_hdr, int interface);
rtable_entry *get_best_route(uint32_t ip_dest);
arp_entry *get_arp_entry(uint32_t ip_dest);
uint32_t ip_to_uint32(char* ip_address);

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
	iphdr* ip_hdr = get_iphdr(frame);
	if (ip_hdr == NULL) {
		return NULL;
	}
	if (ip_hdr->protocol == 1) {
		header = (icmphdr*)((char*)ip_hdr + sizeof(iphdr));
	}
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

void generate_ICMP(ether_header* eth_hdr, iphdr* ip_hdr, icmphdr* icmp_hdr, int interface, uint8_t type) {
	uint8_t l2_source[6];
	uint8_t l2_target[6];
	get_interface_mac(interface, l2_source);
	memcpy(l2_target, eth_hdr->ether_shost, 6);
	uint32_t s_ip = ip_to_uint32(get_interface_ip(interface));
	uint32_t t_ip = ntohl(ip_hdr->saddr);
	uint8_t ipv4_header[20];
	uint8_t datagram_part[8];
	memcpy(ipv4_header, ip_hdr, 20);
	memcpy(datagram_part, ((char*)ip_hdr + sizeof(iphdr)), 8);

	generate_eth_header(eth_hdr, htons(0x800), l2_source, l2_target);
	ip_hdr->check = 0;
	ip_hdr->daddr = htonl(t_ip);
	ip_hdr->frag_off = 0;
	ip_hdr->id = ntohs(1);
	ip_hdr->ihl = 5;
	ip_hdr->protocol = 1;
	ip_hdr->saddr = htonl(s_ip);
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(2 * sizeof(iphdr) + sizeof(icmphdr) + 8);
	ip_hdr->ttl = 255;
	ip_hdr->version = 4;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(iphdr)));

	icmp_hdr = get_icmphdr(eth_hdr);
	icmp_hdr->checksum = 0;
	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	memset((char*)icmp_hdr + 4, 0x00, 4);
	memcpy((char*)icmp_hdr + sizeof(icmphdr), ipv4_header, 20);
	memcpy((char*)icmp_hdr + sizeof(icmphdr) + 20, datagram_part, 8);
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(icmphdr) + sizeof(iphdr) + 8));
}

void generate_ICMP_REPLY(ether_header* eth_hdr, iphdr* ip_hdr, icmphdr* icmp_hdr, int interface) {
	uint8_t l2_source[6];
	uint8_t l2_target[6];
	get_interface_mac(interface, l2_source);
	memcpy(l2_target, eth_hdr->ether_shost, 6);
	uint32_t s_ip = ip_to_uint32(get_interface_ip(interface));
	uint32_t t_ip = ntohl(ip_hdr->saddr);

	generate_eth_header(eth_hdr, htons(0x800), l2_source, l2_target);
	ip_hdr->check = 0;
	ip_hdr->daddr = htonl(t_ip);
	ip_hdr->frag_off = 0;
	ip_hdr->id = ntohs(1);
	ip_hdr->ihl = 5;
	ip_hdr->protocol = 1;
	ip_hdr->saddr = htonl(s_ip);
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(iphdr) + sizeof(icmphdr) + 48);
	ip_hdr->ttl = 255;
	ip_hdr->version = 4;
	ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(iphdr)));

	uint8_t old_icmp[48];
	memcpy(old_icmp, (char*)icmp_hdr + sizeof(icmphdr), 48);
	icmp_hdr = get_icmphdr(eth_hdr);
	icmp_hdr->checksum = 0;
	icmp_hdr->code = 0;
	icmp_hdr->type = 0;
	icmp_hdr->un.echo.id = 0;
	icmp_hdr->un.echo.sequence = 0;
	memcpy((char*)icmp_hdr + sizeof(icmphdr), old_icmp, 48);
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(icmphdr) + 48));
}

rtable_entry *get_best_route(uint32_t ip_dest) {
	rtable_entry *next = NULL;
	uint32_t i = 0; 
	uint32_t j = rtable_len - 1;
	while (i < j) {
		uint32_t m = (i + j) / 2;
		if ((rtable[m].prefix) == (ip_dest & rtable[m].mask)) {
			next = &(rtable[m]);
			i = m + 1;
		}
		if ((rtable[m].prefix) < (ip_dest & rtable[m].mask)) {
			i = m + 1;
		}
		else {
			j = m - 1;
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
				printf("Generating ICMP Time Exceeded\n");

				generate_ICMP(eth_hdr, ip_hdr, icmp_hdr, interface, 11);

				len = sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8;
				send_to_link(interface, buf, len);
				printf("Sent ICMP Time Exceeded\n");

				continue;
			}
			// Updated TTL
			ip_hdr->ttl--;
			printf("ttl\n");

			// Check if the router is the destination
			uint32_t local_ip = ip_to_uint32(get_interface_ip(interface));
			if (local_ip == ntohl(ip_hdr->daddr)) {
				printf("Got ICMP Echo Request\n");
				
				uint16_t len_echo = ntohs(ip_hdr->tot_len) - sizeof(iphdr) - sizeof(icmphdr);
				printf("len echo request data: %d\n", len_echo);

				generate_ICMP_REPLY(eth_hdr, ip_hdr, icmp_hdr, interface);
				
				len = sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr) + 48;
				send_to_link(interface, buf, len);
				printf("Sent ICMP Echo Reply\n");
				continue;
			}

			// Check for next route
			rtable_entry *next_route = get_best_route(ip_hdr->daddr);
			if (next_route == NULL) {
				printf("--Next Route Not Found--\n");
				printf("Generating ICMP Destination Unreachable\n");
				
				generate_ICMP(eth_hdr, ip_hdr, icmp_hdr, interface, 3);

				len = sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8;
				send_to_link(interface, buf, len);
				printf("Sent ICMP Destination Unreachable\n");

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
					}
				}

				if (found == 0) {
					// ARP reply added to cache
					arp_table[arp_table_len++] = arp_reply;
					memset(buf, 0x00, MAX_PACKET_LEN);
					struct queued_pack *queued_pack = queue_deq(arp_queue);
					memcpy(buf, queued_pack->pack, queued_pack->pack_size);
					ip_hdr = get_iphdr(eth_hdr);

					rtable_entry *next_route = get_best_route(ip_hdr->daddr);
					if (next_route == NULL) {
						printf("--Next Route Not Found--\n");
						printf("Generating ICMP Destination Unreachable\n");
						
						generate_ICMP(eth_hdr, ip_hdr, icmp_hdr, interface, 3);

						len = sizeof(ether_header) + 2 * sizeof(iphdr) + sizeof(icmphdr) + 8;
						send_to_link(interface, buf, len);
						printf("Sent ICMP Destination Unreachable\n");

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

		printf("--Router loop ends here--\n");
	}
}

