/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>

// Common definitions for BPF code in the tethering mainline module.
// These definitions are available to:
// - The BPF programs in Tethering/bpf_progs/
// - JNI code that depends on the bpf_connectivity_headers library.

#define BPF_TETHER_ERRORS    \
    ERR(INVALID_IP_VERSION)  \
    ERR(LOW_TTL)             \
    ERR(INVALID_TCP_HEADER)  \
    ERR(TCP_CONTROL_PACKET)  \
    ERR(NON_GLOBAL_SRC)      \
    ERR(NON_GLOBAL_DST)      \
    ERR(LOCAL_SRC_DST)       \
    ERR(NO_STATS_ENTRY)      \
    ERR(NO_LIMIT_ENTRY)      \
    ERR(BELOW_IPV4_MTU)      \
    ERR(BELOW_IPV6_MTU)      \
    ERR(LIMIT_REACHED)       \
    ERR(CHANGE_HEAD_FAILED)  \
    ERR(TOO_SHORT)           \
    ERR(HAS_IP_OPTIONS)      \
    ERR(IS_IP_FRAG)          \
    ERR(CHECKSUM)            \
    ERR(NON_TCP_UDP)         \
    ERR(NON_TCP)             \
    ERR(SHORT_L4_HEADER)     \
    ERR(SHORT_TCP_HEADER)    \
    ERR(SHORT_UDP_HEADER)    \
    ERR(UDP_CSUM_ZERO)       \
    ERR(TRUNCATED_IPV4)      \
    ERR(_MAX)

#define ERR(x) BPF_TETHER_ERR_ ##x,
enum {
    BPF_TETHER_ERRORS
};
#undef ERR

/////// porting from bpf_tethering.h //////////////////////
#define STRUCT_SIZE(name, size) _Static_assert(sizeof(name) == (size), "Incorrect struct size.")

// For now tethering offload only needs to support downstreams that use 6-byte MAC addresses,
// because all downstream types that are currently supported (WiFi, USB, Bluetooth and
// Ethernet) have 6-byte MAC addresses.

typedef struct {
    uint32_t iif;              // The input interface index
    uint8_t dstMac[ETH_ALEN];  // destination ethernet mac address (zeroed iff rawip ingress)
    uint8_t zero[2];           // zero pad for 8 byte alignment
    struct in6_addr neigh6;    // The destination IPv6 address
} TetherDownstream6Key;
STRUCT_SIZE(TetherDownstream6Key, 4 + 6 + 2 + 16);  // 28

typedef struct {
    uint32_t oif;             // The output interface to redirect to
    struct ethhdr macHeader;  // includes dst/src mac and ethertype (zeroed iff rawip egress)
    uint16_t pmtu;            // The maximum L3 output path/route mtu
} Tether6Value;
STRUCT_SIZE(Tether6Value, 4 + 14 + 2);  // 20

typedef struct {
    uint32_t iif;              // The input interface index
    uint8_t dstMac[ETH_ALEN];  // destination ethernet mac address (zeroed iff rawip ingress)
    uint16_t l4Proto;          // IPPROTO_TCP/UDP/...
    struct in6_addr src6;      // source &
    struct in6_addr dst6;      // destination IPv6 addresses
    __be16 srcPort;            // source &
    __be16 dstPort;            // destination tcp/udp/... ports
} TetherDownstream64Key;
STRUCT_SIZE(TetherDownstream64Key, 4 + 6 + 2 + 16 + 16 + 2 + 2);  // 48

typedef struct {
    uint32_t oif;             // The output interface to redirect to
    struct ethhdr macHeader;  // includes dst/src mac and ethertype (zeroed iff rawip egress)
    uint16_t pmtu;            // The maximum L3 output path/route mtu
    struct in_addr src4;      // source &
    struct in_addr dst4;      // destination IPv4 addresses
    __be16 srcPort;           // source &
    __be16 outPort;           // destination tcp/udp/... ports
    uint64_t lastUsed;        // Kernel updates on each use with bpf_ktime_get_boot_ns()
} TetherDownstream64Value;
STRUCT_SIZE(TetherDownstream64Value, 4 + 14 + 2 + 4 + 4 + 2 + 2 + 8);  // 40

typedef struct {
    uint32_t iif;              // The input interface index
    uint8_t dstMac[ETH_ALEN];  // destination ethernet mac address (zeroed iff rawip ingress)
    uint8_t zero[2];           // zero pad for 8 byte alignment
                               // TODO: extend this to include src ip /64 subnet
} TetherUpstream6Key;
STRUCT_SIZE(TetherUpstream6Key, 12);

typedef struct {
    uint32_t iif;              // The input interface index
    uint8_t dstMac[ETH_ALEN];  // destination ethernet mac address (zeroed iff rawip ingress)
    uint16_t l4Proto;          // IPPROTO_TCP/UDP/...
    struct in_addr src4;       // source &
    struct in_addr dst4;       // destination IPv4 addresses
    __be16 srcPort;            // source &
    __be16 dstPort;            // destination TCP/UDP/... ports
} Tether4Key, * PTether4Key;
STRUCT_SIZE(Tether4Key, 4 + 6 + 2 + 4 + 4 + 2 + 2);  // 24

typedef struct {
    uint32_t oif;             // The output interface to redirect to
    struct ethhdr macHeader;  // includes dst/src mac and ethertype (zeroed iff rawip egress)
    uint16_t pmtu;            // Maximum L3 output path/route mtu
    struct in6_addr src46;    // source &                 (always IPv4 mapped for downstream)
    struct in6_addr dst46;    // destination IP addresses (may be IPv4 mapped or IPv6 for upstream)
    __be16 srcPort;           // source &
    __be16 dstPort;           // destination tcp/udp/... ports
    uint64_t last_used;       // Kernel updates on each use with bpf_ktime_get_boot_ns()
} Tether4Value, *PTether4Value;
STRUCT_SIZE(Tether4Value, 4 + 14 + 2 + 16 + 16 + 2 + 2 + 8);  // 64



