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

#include <bpf/bpf.h>
#include "tc_tethering.h"


//$REDIRECT_USER -U /sys/fs/bpf/tc/globals/tun_iface -i $(< /sys/class/net/ipt/ifindex)

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


int main(int argc, char **argv)
{
	const char *downstream_map_pinned_file = "/sys/fs/bpf/tc/globals/tether_downstream4_map";
	const char *upstream_map_pinned_file = "/sys/fs/bpf/tc/globals/tether_upstream4_map";
	int dfd = -1;
	int ufd = -1;
	int ret = -1;

	printf("==== downstream map path: %s ====\n", downstream_map_pinned_file);

	// uplink (downstream ingress)
	// server(8.8.8.8) <- UE: [upstream(192.168.182.128) <- downstream(192.168.60.129)] <- client(192.168.60.1)
	Tether4Key dk4 = {
		.iif = 2, // downstream: sys/class/net/ens33/ifindex
		.l4Proto = IPPROTO_TCP,
		.src4.s_addr = 0xC0A83C01, //client
		.dst4.s_addr = 0X08080808, //server
		.srcPort = 8000, //client
		.dstPort = 7766, //server
	};

	long long unsigned int dst_mac = 0x000c294901e4;
	memcpy(dk4.dstMac, &dst_mac, ETH_ALEN); //downstream
	show_Tether4Key(&dk4, "downstream Tether4 map");

	Tether4Value dv4 ={
		.oif = 3, //upstream: sys/class/net/ens34/ifindex
		.pmtu = 1500,
		.src46.s6_addr32[3] = 0xC0A8B680, //upstream
		.dst46.s6_addr32[3] = 0X08080808, //server
		.srcPort = 8000, //client
		.dstPort = 7766, //server
	};

	memset(&dv4.macHeader, 0x00, sizeof(dv4.macHeader)); //upstream
	show_Tether4Value(&dv4, "downstream Tether4 map");


	printf("===== upstream map path: %s =====\n", upstream_map_pinned_file);
	// downlink (upstream ingress)
	// server(8.8.8.8) -> UE: [upstream(192.168.182.128) -> downstream(192.168.60.129)] -> client(192.168.60.1)
	Tether4Key uk4 = {
		.iif = 3, // upstream: sys/class/net/ens34/ifindex
		.l4Proto = IPPROTO_TCP,
		.src4.s_addr = 0X08080808, //server
		.dst4.s_addr = 0xC0A8B680, //upstream
		.srcPort = 7766, //server
		.dstPort = 8000, //client
	};
	memset(uk4.dstMac, 0x00, ETH_ALEN); //upstream
	show_Tether4Key(&uk4, "upstream Tether4 map");


	Tether4Value uv4 ={
		.oif = 2, //downstream: sys/class/net/ens33/ifindex
		.pmtu = 1500,
		.src46.s6_addr32[3] = 0X08080808, //server
		.dst46.s6_addr32[3] =  0xC0A83C01, //client
		.srcPort = 7766, //server
		.dstPort = 8000, //client
	};

	dst_mac = 0x000c294901e4; //downstream
	memcpy(dk4.dstMac, &dst_mac, ETH_ALEN);

	dst_mac = 0x005056c00001; //client
	memcpy(dk4.dstMac, &dst_mac, ETH_ALEN);

	uv4.macHeader.h_proto = htons(ETH_P_IP);
	show_Tether4Value(&uv4, "upstream Tether4 map");


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
