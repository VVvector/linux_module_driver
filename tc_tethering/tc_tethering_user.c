// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Facebook
 */
#include <linux/unistd.h>
#include <linux/bpf.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include <bpf/bpf.h>
#include "tc_tethering.h"


//$REDIRECT_USER -U /sys/fs/bpf/tc/globals/tun_iface -i $(< /sys/class/net/ipt/ifindex)

#define L4PROTO IPPROTO_TCP
#define PMTU 1500

#define MAC_H_PROTO ETH_P_IP

// server <-> UE[upstream <-> downstream] <-> client
struct server_info {
	struct in_addr ip;
	uint16_t l4_proto;
	uint16_t port;
};
#define SERVER_IP_ADDR "8.8.8.8"
#define SERVER_PORT 60

struct client_info {
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	uint16_t l4_proto;
	uint16_t port;
};
#define CLIENT_MAC "00:50:56:c0:00:01"
#define CLIENT_IP_ADDR "192.168.60.1"
#define CLIENT_PORT 70

struct upstream_info {
	uint32_t if_index;
	struct in_addr ip;
	uint16_t port;
};
#define UPSTREAM_IF 2
#define UPSTREAM_IP_ADDR "192.168.182.128"
#define UPSTREAM_PORT CLIENT_PORT

struct downstream_info {
	uint32_t if_index;
	uint8_t mac[ETH_ALEN];
	uint16_t l3_proto;
	struct in_addr ip;
	uint16_t port;

};
#define DOWNSTREAM_IF 3
#define DOWNSTREAM_MAC "00:0c:29:49:01:ee"
#define DOWNSTREAM_IP_ADDR "192.168.60.129"
#define DOWNSTREAM_PORT SERVER_PORT

#define TETHER_DOWNSTREAM4_MAP_PATH "/sys/fs/bpf/tc/globals/tether_downstream4_map"
#define TETHER_UPSTREAM4_MAP_PATH "/sys/fs/bpf/tc/globals/tether_upstream4_map"


static void show_Tether4Key(PTether4Key k4, const char *map_name)
{
	printf("== %s : Key ==\n", map_name);
	printf("iif=%d, l4Proto=%d, src4.s_addr=0x%08x, dst4.s_addr=0x%08x, srcPort=%d, dstPort=%d\n",
		k4->iif, k4->l4Proto, k4->src4.s_addr, k4->dst4.s_addr, ntohs(k4->srcPort), ntohs(k4->dstPort));
	printf("dstMac = %02x:%02x:%02x:%02x:%02x:%02x\n\n",
		k4->dstMac[0], k4->dstMac[1], k4->dstMac[2], k4->dstMac[3], k4->dstMac[4], k4->dstMac[5]);
}

static void show_Tether4Value(PTether4Value v4, const char *map_name)
{
	printf("== %s : Value ==\n", map_name);
	printf("oif=%d, pmtu=%d, src46.s6_addr32[3]=0x%08x, dst46.s6_addr32[3]=0x%08x, srcPort=%d, dstPort=%d\n",
		v4->oif, v4->pmtu, v4->src46.s6_addr32[3], v4->dst46.s6_addr32[3], ntohs(v4->srcPort), ntohs(v4->dstPort));
	printf("macHeader.h_dest = %02x:%02x:%02x:%02x:%02x:%02x\n",
		v4->macHeader.h_dest[0], v4->macHeader.h_dest[1], v4->macHeader.h_dest[2],
		v4->macHeader.h_dest[3], v4->macHeader.h_dest[4], v4->macHeader.h_dest[5]);
	printf("macHeader.h_source = %02x:%02x:%02x:%02x:%02x:%02x\n",
		v4->macHeader.h_source[0], v4->macHeader.h_source[1], v4->macHeader.h_source[2],
		v4->macHeader.h_source[3], v4->macHeader.h_source[4], v4->macHeader.h_source[5]);
	printf("macHeader.h_proto = %d\n\n", ntohs(v4->macHeader.h_proto));
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void hexstr2mac(char *src, unsigned char *dst)
{
	int i = 0;
	while (i < 6) {
		if(' ' == *src||':'== *src||'"'== *src||'\''== *src) {
			src++;
			continue;
		}

		*(dst + i) = ((hex2num(*src) << 4) | hex2num(*(src + 1)));
		i++;
		src += 2;
	}
}


static void init_link_info(struct server_info *server, struct upstream_info *upstream,
	struct client_info *client, struct downstream_info *downstream)
{
	ulong ip;

	//server info
	ip = inet_addr(SERVER_IP_ADDR);
	memcpy(&server->ip, &ip, 4);
	server->port = SERVER_PORT;
	server->l4_proto = L4PROTO;

	//upstream info
	upstream->if_index = UPSTREAM_IF;
	ip = inet_addr(UPSTREAM_IP_ADDR);
	memcpy(&upstream->ip, &ip, 4);
	upstream->port = UPSTREAM_PORT;

	//clent info
	hexstr2mac(CLIENT_MAC, client->mac);
	ip = inet_addr(CLIENT_IP_ADDR);
	memcpy(&client->ip, &ip, 4);
	client->port = CLIENT_PORT;
	client->l4_proto = L4PROTO;

	//download info
	downstream->if_index = DOWNSTREAM_IF;
	hexstr2mac(DOWNSTREAM_MAC, downstream->mac);
	downstream->l3_proto = MAC_H_PROTO;
	ip = inet_addr(DOWNSTREAM_IP_ADDR);
	memcpy(&downstream->ip, &ip, 4);
	downstream->port = DOWNSTREAM_PORT;
}


static void init_bpf_map_info(
	struct server_info *server, struct upstream_info *upstream,
	struct client_info *client, struct downstream_info *downstream,
	PTether4Key dk4, PTether4Value dv4,
	PTether4Key uk4, PTether4Value uv4)
{
	// TETHER_UPSTREAM4_MAP -- on downstream NIC ingress
	// server <- UE[upstream <- downstream] <- client
	uk4->iif = downstream->if_index;
	uk4->l4Proto = client->l4_proto;
	uk4->src4 = client->ip;
	uk4->dst4 = server->ip;
	uk4->srcPort = htons(client->port);
	uk4->dstPort = htons(server->port);
	memcpy(uk4->dstMac, &downstream->mac, ETH_ALEN);
	show_Tether4Key(uk4, TETHER_UPSTREAM4_MAP_PATH);

	uv4->oif = upstream->if_index;
	uv4->pmtu = 1500; //ETHER_MTU
	uv4->src46.s6_addr32[3] = upstream->ip.s_addr;
	uv4->dst46.s6_addr32[3] = server->ip.s_addr;
	uv4->srcPort = htons(upstream->port);
	uv4->dstPort = htons(server->port);
	memset(&uv4->macHeader, 0x00, sizeof(uv4->macHeader));
	show_Tether4Value(uv4, TETHER_UPSTREAM4_MAP_PATH);

	// TETHER_DOWNSTREAM4_MAP -- on upstream NIC ingress)
	// server -> UE[upstream -> downstream] -> client
	dk4->iif = upstream->if_index;
	dk4->l4Proto = server->l4_proto;
	dk4->src4 = server->ip;
	dk4->dst4 = upstream->ip;
	dk4->srcPort = htons(server->port);
	dk4->dstPort = htons(upstream->port);
	memset(dk4->dstMac, 0x00, ETH_ALEN);
	show_Tether4Key(dk4, TETHER_DOWNSTREAM4_MAP_PATH);

	dv4->oif = downstream->if_index;
	dv4->pmtu = PMTU;
	dv4->src46.s6_addr32[3] = server->ip.s_addr;
	dv4->dst46.s6_addr32[3] = client->ip.s_addr;
	dv4->srcPort = htons(downstream->port);
	dv4->dstPort = htons(client->port);
	memcpy(dv4->macHeader.h_dest, client->mac, ETH_ALEN);
	memcpy(dv4->macHeader.h_source, &downstream->mac, ETH_ALEN);
	dv4->macHeader.h_proto = htons(downstream->l3_proto);
	show_Tether4Value(dv4, TETHER_DOWNSTREAM4_MAP_PATH);

}

static void usage(void)
{
	printf("Usage: tc tethering offload rule setting [...]\n");
	printf("       -C <client> mac_addr ip_addr l4_proto port\n");
	printf("       -S <server> ip_addr l4_proto port\n");
	printf("       -U <upstream> if_id ip_add port\n");
	printf("       -D <downstream> if_id mac_addr l3_proto ip_addr port \n");
}


int main(int argc, char **argv)
{
	const char *downstream_map_pinned_file = TETHER_DOWNSTREAM4_MAP_PATH;
	const char *upstream_map_pinned_file = TETHER_UPSTREAM4_MAP_PATH;
	int dfd = -1;
	int ufd = -1;
	int ret = -1;
	int opt;
	int i = 0;
	ulong ip;
	char *p;
	char *p_end;

	struct server_info server = {0};
	struct upstream_info upstream = {0};
	struct client_info client ={0};
	struct downstream_info downstream = {0};

	Tether4Key dk4 = {0};
	Tether4Value dv4 = {0};
	Tether4Key uk4 = {0};
	Tether4Value uv4 = {0};

	while ((opt = getopt(argc, argv, "F:C:S:U:D:")) != -1) {
		switch (opt) {
		case 'C':
			printf("client: %s\n", optarg);
			i = 0;
			p = strtok(optarg, "-");
			while (p) {
				printf("%s\n", p);
				if (i == 0) {
					hexstr2mac(p, client.mac);
				} else if (i == 1) {
					ip = inet_addr(p);
					memcpy(&client.ip, &ip, 4);
				} else if (i == 2) {
					client.l4_proto = atoi(p);
				} else if (i == 3) {
					client.port = atoi(p);
				}

				i++;
				p = strtok(NULL, "-");
			}
			break;

		case 'S':
			printf("server: %s\n", optarg);
			i = 0;
			p = strtok(optarg, "-");
			while (p) {
				printf("%s\n", p);
				if (i == 0) {
					ip = inet_addr(p);
					memcpy(&server.ip, &ip, 4);
				} else if (i == 1) {
					server.l4_proto = atoi(p);
				} else if (i == 2) {
					server.port = atoi(p);
				}

				i++;
				p = strtok(NULL, "-");
			}
			break;

		case 'U':
			printf("upstream: %s\n", optarg);
			i = 0;
			p = strtok(optarg, "-");
			while (p) {
				printf("%s\n", p);
				if (i == 0) {
					upstream.if_index = atoi(p);
				} else if (i == 1) {
					ip = inet_addr(p);
					memcpy(&upstream.ip, &ip, 4);
				} else if (i == 2) {
					upstream.port = atoi(p);
				}

				i++;
				p = strtok(NULL, "-");
			}
			break;

		case 'D':
			printf("downstream: %s\n", optarg);
			i = 0;
			p = strtok(optarg, "-");
			while (p) {
				printf("%s\n", p);
				if (i == 0) {
					downstream.if_index = atoi(p);
				} else if (i == 1) {
					hexstr2mac(p, downstream.mac);
				} else if (i == 2) {
					//downstream.l3_proto = atoi(p);
					downstream.l3_proto = strtol(p, &p_end, 16);
				} else if (i == 3) {
					ip = inet_addr(p);
					memcpy(&downstream.ip, &ip, 4);
				} else if (i == 4) {
					downstream.port = atoi(p);
				}

				i++;
				p = strtok(NULL, "-");
			}
			break;

		default:
			usage();
			goto out;
		}
	}


	//init_link_info(&server, &upstream, &client, &downstream);

	init_bpf_map_info(&server, &upstream, &client, &downstream, &dk4, &dv4, &uk4, &uv4);

	//update downstream map
	dfd = bpf_obj_get(downstream_map_pinned_file);
	if (dfd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			downstream_map_pinned_file, strerror(errno), errno);
		goto out;
	}

	/* bpf_tunnel_key.remote_ipv4 expects host byte orders */
	ret = bpf_map_update_elem(dfd, &dk4, &dv4, 0);
	if (ret) {
		perror("bpf_map_update_elem");
		goto out;
	}

	//update upstream map
	ufd = bpf_obj_get(upstream_map_pinned_file);
	if (ufd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			upstream_map_pinned_file, strerror(errno), errno);
		goto out;
	}

	/* bpf_tunnel_key.remote_ipv4 expects host byte orders */
	ret = bpf_map_update_elem(ufd, &uk4, &uv4, 0);
	if (ret) {
		perror("bpf_map_update_elem");
		goto out;
	}
out:
	if (ufd != -1)
		close(ufd);
	if (dfd != -1)
		close(dfd);

	return ret;
}
