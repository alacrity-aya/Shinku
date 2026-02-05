#pragma once

// XDP Actions
#define XDP_DROP 0
#define XDP_ABORTED 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

// DNS
#define DNS_PORT 53
#define MAX_DNS_NAME_LEN 255

// FNV-1a Hash Constants
#define FNV_OFFSET_BASIS_32 2166136261UL
#define FNV_PRIME_32 16777619UL

// ETH
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/
