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

// server <-> UE[upstream <-> downstream] <-> client
struct server_info {
	struct in_addr ip;
	__be16 port;
};
#define SERVER_IP_ADDR "8.8.8.8"
#define SERVER_PORT 60

struct client_info {
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	__be16 port;
};
#define CLIENT_MAC "00:50:56:c0:00:01"
#define CLIENT_IP_ADDR "192.168.60.1"
#define CLIENT_PORT 70

struct upstream_info {
	uint32_t if_index;
	struct in_addr ip;
	__be16 port;
};
#define UPSTREAM_IF 2
#define UPSTREAM_IP_ADDR "192.168.182.128"
#define UPSTREAM_PORT SERVER_PORT

struct downstream_info {
	uint32_t if_index;
	uint8_t mac[ETH_ALEN];
	struct in_addr ip;
	__be16 port;

};
#define DOWNSTREAM_IF 3
#define DOWNSTREAM_MAC "00:0c:29:49:01:e4"
#define DOWNSTREAM_IP_ADDR "192.168.60.129"
#define DOWNSTREAM_PORT CLIENT_PORT

#define TETHER_DOWNSTREAM4_MAP_PATH "/sys/fs/bpf/tc/globals/tether_downstream4_map"
#define TETHER_UPSTREAM4_MAP_PATH "/sys/fs/bpf/tc/globals/tether_upstream4_map";

#define L4PROTO IPPROTO_TCP
#define PMTU 1500

#define MAC_H_PROTO ETH_P_IP


static void show_Tether4Key(PTether4Key k4, const char *map_name)
{
	printf("== %s : Key ==\n", map_name);
	printf("iif=%d, l4Proto=%d, src4.s_addr=0x%08x, dst4.s_addr=0x%08x, srcPort=%d, dstPort=%d\n",
		k4->iif, k4->l4Proto, k4->src4.s_addr, k4->dst4.s_addr, k4->srcPort, k4->dstPort);
	printf("dstMac = %02x:%02x:%02x:%02x:%02x:%02x\n\n",
		k4->dstMac[0], k4->dstMac[1], k4->dstMac[2], k4->dstMac[3], k4->dstMac[4], k4->dstMac[5]);
}

static void show_Tether4Value(PTether4Value v4, const char *map_name)
{
	printf("== %s : Value ==\n", map_name);
	printf("oif=%d, pmtu=%d, src46.s6_addr32[3]=0x%08x, dst46.s6_addr32[3]=0x%08x, srcPort=%d, dstPort=%d\n",
		v4->oif, v4->pmtu, v4->src46.s6_addr32[3], v4->dst46.s6_addr32[3], v4->srcPort, v4->dstPort);
	printf("macHeader.h_dest = %02x:%02x:%02x:%02x:%02x:%02x\n",
		v4->macHeader.h_dest[0], v4->macHeader.h_dest[1], v4->macHeader.h_dest[2],
		v4->macHeader.h_dest[3], v4->macHeader.h_dest[4], v4->macHeader.h_dest[5]);
	printf("macHeader.h_source = %02x:%02x:%02x:%02x:%02x:%02x\n",
		v4->macHeader.h_source[0], v4->macHeader.h_source[1], v4->macHeader.h_source[2],
		v4->macHeader.h_source[3], v4->macHeader.h_source[4], v4->macHeader.h_source[5]);
	printf("macHeader.h_proto = %d\n\n", v4->macHeader.h_proto);
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
	server->port = htons(SERVER_PORT);

	//upstream info
	upstream->if_index = UPSTREAM_IF;
	ip = inet_addr(UPSTREAM_IP_ADDR);
	memcpy(&upstream->ip, &ip, 4);
	upstream->port = htons(UPSTREAM_PORT);

	//clent info
	hexstr2mac(CLIENT_MAC, client->mac);
	ip = inet_addr(CLIENT_IP_ADDR);
	memcpy(&client->ip, &ip, 4);
	client->port = htons(CLIENT_PORT);

	//download info
	downstream->if_index = DOWNSTREAM_IF;
	hexstr2mac(DOWNSTREAM_MAC, downstream->mac);
	ip = inet_addr(DOWNSTREAM_IP_ADDR);
	memcpy(&downstream->ip, &ip, 4);
	downstream->port = htons(DOWNSTREAM_PORT);	
}

static void init_bpf_map_info(
	struct server_info *server, struct upstream_info *upstream,
	struct client_info *client, struct downstream_info *downstream,
	PTether4Key dk4, PTether4Value dv4,
	PTether4Key uk4, PTether4Value uv4)
{
	// uplink (downstream NIC ingress)
	// server <- UE[upstream <- downstream] <- client
	dk4->iif = downstream->if_index;
	dk4->l4Proto = L4PROTO;
	dk4->src4 = client->ip;
	dk4->dst4 = server->ip;
	dk4->srcPort = client->port;
	dk4->dstPort = server->port;
	memcpy(dk4->dstMac, &downstream->mac, ETH_ALEN);
	show_Tether4Key(dk4, "downstream Tether4 map");

	dv4->oif = upstream->if_index;
	dv4->pmtu = 1500;
	dv4->src46.s6_addr32[3] = upstream->ip.s_addr;
	dv4->dst46.s6_addr32[3] = server->ip.s_addr;
	dv4->srcPort = upstream->port;
	dv4->dstPort = server->port;
	memset(&dv4->macHeader, 0x00, sizeof(dv4->macHeader));
	show_Tether4Value(dv4, "downstream Tether4 map");

	// downlink (upstream NIC ingress)
	// server -> UE[upstream -> downstream] -> client
	uk4->iif = upstream->if_index;
	uk4->l4Proto = L4PROTO;
	uk4->src4 = server->ip;
	uk4->dst4 = upstream->ip;
	uk4->srcPort = server->port;
	uk4->dstPort = client->port;
	memset(uk4->dstMac, 0x00, ETH_ALEN);
	show_Tether4Key(uk4, "upstream Tether4 map");

	uv4->oif = downstream->if_index;
	uv4->pmtu = PMTU;
	uv4->src46.s6_addr32[3] = server->ip.s_addr;
	uv4->dst46.s6_addr32[3] = client->ip.s_addr;
	uv4->srcPort = server->port;
	uv4->dstPort = client->port;
	memcpy(uv4->macHeader.h_dest, client->mac, ETH_ALEN);
	memcpy(uv4->macHeader.h_source, &downstream->mac, ETH_ALEN);
	uv4->macHeader.h_proto = htons(MAC_H_PROTO);
	show_Tether4Value(uv4, "upstream Tether4 map");

}


int main(int argc, char **argv)
{
	const char *downstream_map_pinned_file = TETHER_DOWNSTREAM4_MAP_PATH;
	const char *upstream_map_pinned_file = TETHER_UPSTREAM4_MAP_PATH;
	int dfd = -1;
	int ufd = -1;
	int ret = -1;

	struct server_info server = {0};
	struct upstream_info upstream = {0};
	struct client_info client ={0};
	struct downstream_info downstream = {0};

	Tether4Key dk4 = {0};
	Tether4Value dv4 = {0};
	Tether4Key uk4 = {0};
	Tether4Value uv4 = {0};
	

	init_link_info(&server, &upstream, &client, &downstream);
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
