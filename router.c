// Copyright Arpasanu Emilia-Oana 321 CA 2023 (emilia.arpasanu@stud.acs.upb.ro)
#include "include/queue.h"
#include "include/lib.h"
#include "include/protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define FORMAT_ADDR_TYPE 1
#define IP_PROTOCOL 1
#define DEFAULT_TTL 64
#define ICMP_REPLY_CODE 0
#define ICMP_REPLY_TYPE 0
#define ICMP_DEST_UNREACH_TYPE 3
#define ICMP_TTL_EXCEEDED_TYPE 11
#define HARWDARE_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_REPLY 2
#define ARP_REQUEST 1

struct packet_info
{
	char data[MAX_PACKET_LEN]; // continutul efectiv al pachetului (headere + payload)
	size_t length;			   // lungimea pachetului
};

typedef struct packet_info packet_info;

// tabela de rutare
struct route_table_entry *rtable;
// numarul de intrari din tabela de rutare
int rtable_len;

// tabela MAC
struct arp_entry *mac_table;
// cate intrari poate avea in total tabela ARP la un moment dat (valoare initializata)
int mac_table_size = 100;
// numarul de intrari din tabela ARP (la un moment dat)
int mac_table_len;

// functia returneaza adresa catre intrarea din tabela ARP corespunzatoare adresei IP cautate
// (daca aceasta nu exista se va intoarce NULL)
struct arp_entry *get_mac_entry(uint32_t given_ip)
{
	struct arp_entry *mac = NULL;
	int i;

	for (i = 0; i < mac_table_len; i++)
		if (mac_table[i].ip == given_ip)
			mac = &(mac_table[i]);

	return mac;
}

// functia este utilizata pentru a defini ordinea pe care ar trebui sa le aiba
// in tabela de rutare (crescatoare in functie de prefixele adreselor IP, iar in caz de egalitate
// in functie de masti)
int compar(void const *a, void const *b)
{
	struct route_table_entry const *x = (struct route_table_entry *)a;
	struct route_table_entry const *y = (struct route_table_entry *)b;

	if (ntohl(x->prefix & x->mask) > ntohl(y->prefix & y->mask))
		return 1;
	if (ntohl(x->prefix & x->mask) < ntohl(y->prefix & y->mask))
		return -1;

	// prefixe egale: se compara mastile

	if (ntohl(x->mask) > ntohl(y->mask))
		return 1;
	if (ntohl(x->mask) < ntohl(y->mask))
		return -1;
	
	return 0;
}

// functia cauta binar intrarea din tabela de rutare ce are cel mai mare prefix comun cu adresa IP cautata
// (in cazul in care nu se identifica niciun prefix comun se intoarce NULL - valoarea initiala a lui last_find)
struct route_table_entry *search_route(struct route_table_entry *last_find, int l, int r, uint32_t given_ip)
{
	int mid = (l + r) / 2;

	if (l <= r)
	{
		if (ntohl(rtable[mid].mask & rtable[mid].prefix) == ntohl(rtable[mid].mask & given_ip))
			return search_route(&(rtable[mid]), mid + 1, r, given_ip);
		if (ntohl(rtable[mid].mask & rtable[mid].prefix) > ntohl(rtable[mid].mask & given_ip))
			return search_route(last_find, l, mid - 1, given_ip);
		if (ntohl(rtable[mid].mask & rtable[mid].prefix) < ntohl(rtable[mid].mask & given_ip))
			return search_route(last_find, mid + 1, r, given_ip);
	}

	return last_find;
}

// functia returneaza intrarea din tabela de rutare corespunzatoare adresei IP cautate
struct route_table_entry *get_route(uint32_t given_ip)
{
	struct route_table_entry *result = NULL;

	result = search_route(NULL, 0, rtable_len - 1, given_ip);

	return result;
}

// functia verifica daca un pachet este destinat routerului (el este fie destinatarul final, fie un hop intermediar)
int check_mac(struct ether_header *eth_hdr, int recv_interface)
{
	uint8_t router_mac[6];
	int ok1 = 1, ok2 = 1, i;

	get_interface_mac(recv_interface, router_mac);

	// verificare adresa_MAC_destinatie == adresa_MAC_router
	for (i = 0; i < 6 && ok1; i++)
		if (router_mac[i] != eth_hdr->ether_dhost[i])
			ok1 = 0;

	// verificare dresa_MAC_destinatie == adresa de broadcast
	for (i = 0; i < 6 && ok2; i++)
		if (eth_hdr->ether_dhost[i] != 255)
			ok2 = 0;

	if (!ok1 && !ok2)
		return -1;

	return 1;
}

// functia creeaza un pahcet de tip ICMP ce semnaleaza o eroare a pachetului primit
// ce va trebui sa fie aruncat (TTL <=1 sau destinatia nu exista)
void create_error_icmp_packet(int recv_interface, char packet[MAX_PACKET_LEN], char dropped_packet[MAX_PACKET_LEN], size_t *packet_len, int error_type)
{
	struct ether_header new_eth_hdr, *old_eth_hdr;
	struct iphdr new_ip_hdr, *old_ip_hdr;
	struct icmphdr new_icmp_hdr;
	uint8_t router_mac[6];

	old_eth_hdr = (struct ether_header *)dropped_packet;
	old_ip_hdr = (struct iphdr *)(dropped_packet + sizeof(struct ether_header));

	get_interface_mac(recv_interface, router_mac);

	// 1. construiesc noul antet Ethernet
	memcpy(new_eth_hdr.ether_shost, router_mac, sizeof(new_eth_hdr.ether_shost));
	memcpy(new_eth_hdr.ether_dhost, old_eth_hdr->ether_shost, sizeof(new_eth_hdr.ether_dhost));

	new_eth_hdr.ether_type = htons(ETHERTYPE_IP);

	// 2. contruiesc antetul de tip ICMP
	// tip eroare = 1 -> destination unreachable
	// tip eroare = 2 -> time-to-live exceeded

	if (error_type == 1)
	{
		new_icmp_hdr.code = ICMP_REPLY_CODE;
		new_icmp_hdr.type = ICMP_DEST_UNREACH_TYPE;
	}

	if (error_type == 2)
	{
		new_icmp_hdr.code = ICMP_REPLY_CODE;
		new_icmp_hdr.type = ICMP_TTL_EXCEEDED_TYPE;
	}

	memset(&(new_icmp_hdr.un), 0, sizeof(new_icmp_hdr.un));

	// 3. construiesc antetul nou de tip IPv4
	memcpy(&new_ip_hdr, old_ip_hdr, sizeof(struct iphdr));

	uint32_t aux;
	aux = new_ip_hdr.saddr;
	new_ip_hdr.saddr = new_ip_hdr.daddr;
	new_ip_hdr.daddr = aux;

	new_ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr.protocol = IP_PROTOCOL;
	new_ip_hdr.ttl = DEFAULT_TTL;

	// se calculeaza noul checksum al antetului IPv4
	new_ip_hdr.check = 0;
	new_ip_hdr.check = htons(checksum((uint16_t *)(&new_ip_hdr), sizeof(struct iphdr)));

	// se calculeaza checksum-ul antetului ICMP
	new_icmp_hdr.checksum = 0;
	new_icmp_hdr.checksum = htons(checksum((uint16_t *)(&new_icmp_hdr), sizeof(struct icmphdr)));

	// numarul de octeti dupa care se regaseste payload-ul pachetului aruncat
	size_t len = sizeof(struct ether_header) + sizeof(struct iphdr);

	// construiesc pachetul
	memset(packet, 0, MAX_PACKET_LEN);

	memcpy(packet, &new_eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &new_ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), &new_icmp_hdr, sizeof(struct icmphdr));

	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr));

	// se copiaza drept payload primii 8 octeti din vechile date ale pachetului aruncat
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr), dropped_packet + len, 8);

	// lungimea pachetului rezultat
	*packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
}

// functia creeaza un pahcet de tip ICMP ce reprezinta raspunsul de tip "Echo reply"
void create_reply_icmp_packet(int recv_interface, char packet[MAX_PACKET_LEN], char dropped_packet[MAX_PACKET_LEN], size_t *packet_len, size_t dropped_packet_len)
{
	struct ether_header new_eth_hdr, *old_eth_hdr;
	struct iphdr *old_ip_hdr, new_ip_hdr;
	struct icmphdr new_icmp_hdr, *old_icmp_hdr;
	uint8_t router_mac[6];

	old_eth_hdr = (struct ether_header *)dropped_packet;
	old_ip_hdr = (struct iphdr *)(dropped_packet + sizeof(struct ether_header));
	old_icmp_hdr = (struct icmphdr *)(dropped_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	get_interface_mac(recv_interface, router_mac);

	// 1. construiesc noul antet Ethernet
	memcpy(new_eth_hdr.ether_shost, router_mac, sizeof(new_eth_hdr.ether_shost));
	memcpy(new_eth_hdr.ether_dhost, old_eth_hdr->ether_shost, sizeof(new_eth_hdr.ether_dhost));

	new_eth_hdr.ether_type = htons(ETHERTYPE_IP);

	// 2. construiesc noul antet de tip IPv4
	memcpy(&new_ip_hdr, old_ip_hdr, sizeof(struct iphdr));

	uint32_t aux;
	aux = new_ip_hdr.saddr;
	new_ip_hdr.saddr = new_ip_hdr.daddr;
	new_ip_hdr.daddr = aux;

	new_ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ip_hdr.protocol = IP_PROTOCOL;
	new_ip_hdr.ttl = DEFAULT_TTL;

	// se calculeaza noul checksum al antetului IPv4
	new_ip_hdr.check = 0;
	new_ip_hdr.check = htons(checksum((uint16_t *)(&new_ip_hdr), sizeof(struct iphdr)));

	// 3. contruiesc antetul de tip ICMP
	new_icmp_hdr.code = ICMP_REPLY_CODE;
	new_icmp_hdr.type = ICMP_REPLY_TYPE;

	// se copiaza vechile date din antetul ICMP al pachetului la care se va raspunde: id si numar de secventa
	memset(&(new_icmp_hdr.un), 0, sizeof(new_icmp_hdr.un));
	memcpy(&(new_icmp_hdr.un.echo), &(old_icmp_hdr->un.echo), sizeof(new_icmp_hdr.un.echo));

	// se calculeaza checksum-ul antetului ICMP
	new_icmp_hdr.checksum = 0;
	new_icmp_hdr.checksum = htons(checksum((uint16_t *)(&new_icmp_hdr), sizeof(struct icmphdr)));

	// lungimea tuturor headerelor ale pachetului primit
	size_t len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	// contruiesc pachetul
	memset(packet, 0, MAX_PACKET_LEN);

	memcpy(packet, &new_eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &new_ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), &new_icmp_hdr, sizeof(struct icmphdr));

	// se copiaza in noul pachet toate datele din cel primit
	memcpy(packet + len, old_ip_hdr + sizeof(struct iphdr), dropped_packet_len - len);

	// lungimea pachetului rezultat
	*packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + (dropped_packet_len - len);
}

// functia creeaza un pachet de tip ARP request pentru a determina adresa MAC a urmatorului hop
// in drumul pachetului catre destinatie
void create_arp_request(struct route_table_entry *best_route, char packet[MAX_PACKET_LEN], size_t *arp_len)
{
	struct ether_header eth_hdr;
	struct arp_header arp_hdr;

	uint8_t next_hop_mac[6];
	uint8_t broadcast_mac[6];

	get_interface_mac(best_route->interface, next_hop_mac);

	// 1. creez antetul de tip Ethernet
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);
	memcpy(eth_hdr.ether_shost, next_hop_mac, sizeof(eth_hdr.ether_shost));

	memset(broadcast_mac, 255, sizeof(broadcast_mac));
	memcpy(eth_hdr.ether_dhost, broadcast_mac, sizeof(eth_hdr.ether_dhost));

	// 2. creez antetul de tip ARP
	arp_hdr.htype = htons(FORMAT_ADDR_TYPE);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.hlen = HARWDARE_ADDR_LEN;
	arp_hdr.plen = IP_ADDR_LEN;
	arp_hdr.op = htons(ARP_REQUEST);

	memcpy(arp_hdr.sha, next_hop_mac, sizeof(arp_hdr.sha));
	arp_hdr.spa = inet_addr(get_interface_ip(best_route->interface));

	memset(arp_hdr.tha, 0, sizeof(arp_hdr.tha));	// default gateway
	arp_hdr.tpa = best_route->next_hop;

	// 3. construiesc pachetul ARP request
	memset(packet, 0, MAX_PACKET_LEN);

	memcpy(packet, &eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// lungimea pachetului
	*arp_len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

// functia creeaza un pachet de tip ARP reply pentru a transmite adresa MAC a urmatorului hop
// in drumul pachetului catre destinatie (in acest caz routerul)
void create_arp_reply(int recv_interface, char arp_packet[MAX_PACKET_LEN], char packet[MAX_PACKET_LEN], size_t *arp_len)
{
	struct ether_header eth_hdr, *old_eth_hdr;
	struct arp_header arp_hdr, *old_arp_hdr;

	uint8_t router_mac[6];

	get_interface_mac(recv_interface, router_mac);

	old_eth_hdr = (struct ether_header *)arp_packet;
	old_arp_hdr = (struct arp_header *)(arp_packet + sizeof(struct ether_header));

	// 1. creez header-ul de tip Ethernet
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	memcpy(eth_hdr.ether_dhost, old_eth_hdr->ether_shost, sizeof(eth_hdr.ether_dhost));
	memcpy(eth_hdr.ether_shost, router_mac, sizeof(eth_hdr.ether_shost));

	// 2. creez header-ul de tip ARP
	arp_hdr.htype = htons(FORMAT_ADDR_TYPE);
	arp_hdr.ptype = htons(ETHERTYPE_IP);
	arp_hdr.hlen = HARWDARE_ADDR_LEN;
	arp_hdr.plen = IP_ADDR_LEN;
	arp_hdr.op = htons(ARP_REPLY);

	memcpy(arp_hdr.sha, router_mac, sizeof(arp_hdr.sha));
	arp_hdr.spa = old_arp_hdr->tpa;
	memcpy(arp_hdr.tha, old_eth_hdr->ether_shost, sizeof(arp_hdr.tha));
	arp_hdr.tpa = old_arp_hdr->spa;

	// 3. copiez antetele in pachetul ARP reply
	memset(packet, 0, MAX_PACKET_LEN);

	memcpy(packet, &eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// lungimea pachetului
	*arp_len = sizeof(struct ether_header) + sizeof(struct arp_header);
}

// functia adauga in vectorul de pachete ce sunt adaugate in coada un nou pachet ce trebuie pastrat
void keep_packet(packet_info **kept_packets, int *kept_packets_size, int *kept_packets_len, packet_info packet)
{
	packet_info *new_kept_packets;
	int i;

	// redimensionarea vectorului (daca este cazul)
	if ((*kept_packets_len + 1) >= *kept_packets_size)
	{
		new_kept_packets = (packet_info *)calloc(2 * (*kept_packets_size), sizeof(packet_info));

		for (i = 0; i < *kept_packets_len; i++)
			memcpy(&(new_kept_packets[i]), &((*kept_packets)[i]), sizeof(packet_info));

		// copierea in intregime a pachetului la sfarsitul vectorului
		memcpy(&(new_kept_packets[*kept_packets_len]), &packet, sizeof(packet_info));

		*kept_packets_len = *kept_packets_len + 1;
		*kept_packets_size = *kept_packets_size * 2;

		// eliberarea vechii zonei de memorie
		free(*kept_packets);

		// inlocuirea vechiului vector cu cel nou creat
		*kept_packets = new_kept_packets;
	}
	else // nu este nevoie de redimensionare
	{
		// adaugarea efectiva a pachetului la sfarsit
		memcpy(&((*kept_packets)[*kept_packets_len]), &packet, sizeof(packet_info));

		*kept_packets_len = *kept_packets_len + 1;
	}
}

// functia adauga in tabela ARP o noua intrare: adresa IP si adresa MAC corespunzatoare
void add_mac_entry(struct arp_entry **mac_table, uint32_t ip_address, uint8_t mac_address[6])
{
	struct arp_entry *new_mac_table;
	int i;

	// redimensionarea tabelei (daca este cazul)
	if ((mac_table_len + 1) >= mac_table_size)
	{
		new_mac_table = (struct arp_entry *)malloc(2 * mac_table_size * sizeof(struct arp_entry));

		for (i = 0; i < mac_table_len; i++)
			memcpy(&(new_mac_table[i]), &((*mac_table)[i]), sizeof(struct arp_entry));

		// construiesc intrarea noua din tabela MAC
		struct arp_entry new_entry;

		new_entry.ip = ip_address;
		memcpy(new_entry.mac, mac_address, sizeof(new_entry.mac));

		// pun intrarea noua in tabela noua
		memcpy(&(new_mac_table[mac_table_len]), &new_entry, sizeof(struct arp_entry));

		mac_table_len += 1;
		mac_table_size *= 2;

		// eliberarea vechii zonei de memorie
		free(*mac_table);

		// inlocuirea vechii tabele cu cea noua
		*mac_table = new_mac_table;
	}
	else
	{
		// construiesc intrarea noua din tabela MAC
		struct arp_entry new_entry;

		new_entry.ip = ip_address;
		memcpy(new_entry.mac, mac_address, sizeof(new_entry.mac));

		// pun intrarea noua in tabela
		memcpy(&((*mac_table)[mac_table_len]), &new_entry, sizeof(struct arp_entry));

		mac_table_len += 1;
	}
}

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];
	char arp_packet[MAX_PACKET_LEN];
	char icmp_packet[MAX_PACKET_LEN];

	size_t packet_len, arp_len, icmp_len;

	// interfata pe care se primeste pachetul
	int interface;

	// coada de pachete pentru care se asteapta MAC-ul destinatie
	queue packet_queue;

	// vector pentru pachetele care vor fi puse in coada ARP in asteptarea adresei MAC destinatie (next hop)
	packet_info *kept_packets;

	// numarul maxim de pachete ce poate fi stocat la un moment dat in vectorul de pachete si lungimea lui curenta
	int kept_packets_size = 1000, kept_packets_len = 0;

	init(argc - 2, argv + 2);

	// alocarea si citirea tabelei de rutare
	rtable = malloc(sizeof(struct route_table_entry) * 100000);

	DIE(rtable == NULL, "memory");

	rtable_len = read_rtable(argv[1], rtable);

	// sortarea tabelei de rutare pentru algoritmul LPM
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compar);

	// tabela ARP ce se construieste
	mac_table = malloc(sizeof(struct arp_entry) * mac_table_size);

	DIE(mac_table == NULL, "memory");

	// aloc memorie pentru coada de pachete si vectorul de pachete
	packet_queue = queue_create();
	kept_packets = (packet_info *)calloc(kept_packets_size, sizeof(packet_info));

	while (1)
	{
		// primire pachet
		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "recv_from_any_links");

		// pointer catre antetul de tip Ethernet
		struct ether_header *eth_hdr = (struct ether_header *)packet;

		// daca pachetul nu este pentru router, se arunca
		if (check_mac(eth_hdr, interface) < 0) 
			continue;

		struct iphdr *ip_hdr = NULL;
		struct arp_header *arp_hdr = NULL;

		// am primit un pachet de tip ARP
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP))
		{
			arp_hdr = (struct arp_header *)(packet + sizeof(struct ether_header));

			// pachetul nu este pentru router; il trimit catre urmatorul hop
			if (arp_hdr->tpa != inet_addr(get_interface_ip(interface)))
			{
				struct route_table_entry *best_route = NULL;

				best_route = get_route(arp_hdr->tpa);

				if (!best_route)
					continue;

				send_to_link(best_route->interface, packet, packet_len);

				continue;
			}

			// routerul a primit un ARP reply; trebuie sa se adauge o noua intrare in tabela ARP
			if (arp_hdr->op == htons(ARP_REPLY))
			{
				add_mac_entry(&mac_table, arp_hdr->spa, arp_hdr->sha);

				// se trimit pachetele din coada care au adresa IP destinatie cea corespunzatoare intrarii noi
				int send_front_packet = 1;	// procesul se opreste cand in coada incepe o secventa de pachete pentru care nu se stie adresa MAC
				packet_info *front_packet;	// primul pachet din coada (cel curent)

				while (!queue_empty(packet_queue) && send_front_packet)
				{
					front_packet = (packet_info *)queue_front(packet_queue);

					// pointer catre datele pachetului curent
					char *packet_data = front_packet->data;

					// pointeri catre headerele de ip Ethernet si IPv4 ale pachetului curent
					struct iphdr *packet_ip_hdr = NULL;
					struct ether_header *packet_eth_hdr = NULL;
					struct route_table_entry *best_route = NULL;

					packet_eth_hdr = (struct ether_header *)packet_data;
					packet_ip_hdr = (struct iphdr *)(packet_data + sizeof(struct ether_header));

					// se cauta urmatorul hop catre care trebuie sa se trimita pachetul
					best_route = get_route(packet_ip_hdr->daddr);

					// nu a fost gasit drum pentru pachetul curent
					if (!best_route) 
						send_front_packet = 0;
					else
					{
						struct arp_entry *packet_mac_addr = NULL;

						packet_mac_addr = get_mac_entry(best_route->next_hop);

						// nu a fost gasit inca adresa MAC catre care se trimite pachetul
						if (!packet_mac_addr)
							send_front_packet = 0;
						else
						{
							// se acutalizeaza adresele MAC sursa si destinatie a pachetului
							memcpy(packet_eth_hdr->ether_dhost, packet_mac_addr->mac, sizeof(packet_mac_addr->mac));

							get_interface_mac(best_route->interface, packet_eth_hdr->ether_shost);

							// se trimite pachetul catre hop-ul urmator
							send_to_link(best_route->interface, packet_data, front_packet->length);

							// se scoate pachetul din coada
							queue_deq(packet_queue);
						}
					}
				}

				continue;
			}

			// routerul a primit un ARP request pentru MAC-ul propriu
			if (arp_hdr->op == htons(ARP_REQUEST))
			{
				// se construieste ARP reply-ul si se trimite catre host-ul ce l-a cerut
				create_arp_reply(interface, packet, arp_packet, &arp_len);

				send_to_link(interface, arp_packet, arp_len);

				continue;
			}
		}

		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP))
		{
			// pointer catre antetul de tip IPv4
			ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

			// 1. verificare daca pachetul IPv4 curent este corupt
			uint16_t sum_check = ntohs(ip_hdr->check);

			ip_hdr->check = 0;
			uint16_t new_sum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			// pachetul se arunca, intrucat el a fost corupt
			if (sum_check != new_sum)
				continue;

			// 3. se verifica TTL-ul pachetului
			uint8_t packet_ttl = ip_hdr->ttl;

			// pachetul nu mai poate fi trimis altor hop-uri; se trimite un pachet de tip ICMP
			// emitatorului ce anunta eroarea produsa
			if (packet_ttl <= 1)
			{
				create_error_icmp_packet(interface, icmp_packet, packet, &icmp_len, 2);
				send_to_link(interface, icmp_packet, icmp_len);

				continue;
			}

			// daca pachetul mai poate fi trimis si altor hop-uri, se actualizeaza TTL
			ip_hdr->ttl = ip_hdr->ttl - 1;

			// se recalculeaza checksum-ul
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// 2. se cauta urmatorul hop pana la destinatia finala a pachetului
			struct route_table_entry *best_route = get_route(ip_hdr->daddr);

			// daca nu exista un urmator hop catre care ar trebui trimis pachetul,
			// se trimite un pachet de tip ICMP emitatorului ce anunta eroarea produsa
			if (!best_route)
			{
				create_error_icmp_packet(interface, icmp_packet, packet, &icmp_len, 1);
				send_to_link(interface, icmp_packet, icmp_len);

				continue;
			}

			// daca pachetul este de tip "Echo request" (este un mesaj destinat routerului),
			// se raspunde emitatorului cu un pachet de tip "Echo reply"
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr)
			{
				create_reply_icmp_packet(interface, icmp_packet, packet, &icmp_len, packet_len);
				send_to_link(interface, icmp_packet, icmp_len);

				continue;
			}

			struct arp_entry *mac_addr = NULL;

			// se cauta adresa MAC destinatie a pachetului
			mac_addr = get_mac_entry(best_route->next_hop);

			// daca adresa MAC nu a fost gasita in tabela ARP, se trimite un request ARP host-urilor vecine pentru a o afla
			if (!mac_addr)
			{
				// se creeaza o noua structura de pachet care retine continutul si lungimea sa
				packet_info queue_packet;

				memcpy(queue_packet.data, packet, packet_len);
				queue_packet.length = packet_len;

				// pastrez pachetul intr-un vector de pachete (in coada adaug doar pointeri catre pachetele corespunzatoare)
				keep_packet(&kept_packets, &kept_packets_size, &kept_packets_len, queue_packet);

				// se adauga pachetul in coada de asteptare
				queue_enq(packet_queue, &(kept_packets[kept_packets_len - 1]));

				// se creeaza si trimite request-ul ARP
				create_arp_request(best_route, arp_packet, &arp_len);

				send_to_link(best_route->interface, arp_packet, arp_len);

				continue;
			}

			// daca adresa MAC destinatie a pachetului este cunoscuta, se actualizeaza
			// adresele MAC sursa si destinatie din antetul Ethernet
			memcpy(eth_hdr->ether_dhost, mac_addr->mac, sizeof(mac_addr->mac));

			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			// pachetul este trimis catre urmatorul hop
			send_to_link(best_route->interface, packet, packet_len);
		}
	}

	free(packet_queue);
	free(kept_packets);
	free(mac_table);
	free(rtable);
}
