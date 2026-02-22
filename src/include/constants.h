#pragma once

// XDP Actions
#define XDP_DROP 0
#define XDP_ABORTED 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

// TC Actions
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

// DNS
#define DNS_PORT 53
#define MAX_DNS_NAME_LEN 255
#define MAX_DNS_CAPTURE_LEN 1024
#define MAX_DNS_LABEL_ITERATIONS 100 /* Max iterations for DNS name parsing */

// DNS Header Flags (Host Byte Order)
#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_TC 0x0200 // Truncated bit
#define DNS_RCODE_MASK 0x000F

/* DNS Resource Record Types */
#define DNS_TYPE_A 1 /* IPv4 Address */
#define DNS_TYPE_NS 2 /* Authoritative Name Server */
#define DNS_TYPE_CNAME 5 /* Canonical Name for an alias */
#define DNS_TYPE_SOA 6 /* Start of a zone of authority */
#define DNS_TYPE_PTR 12 /* Domain name pointer (Reverse DNS) */
#define DNS_TYPE_MX 15 /* Mail exchange */
#define DNS_TYPE_TXT 16 /* Text strings */
#define DNS_TYPE_AAAA 28 /* IPv6 Address */
#define DNS_TYPE_SRV 33 /* Server selection */

// FNV-1a Hash Constants
#define FNV_OFFSET_BASIS_32 2166136261UL
#define FNV_PRIME_32 16777619UL

// ETH
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
#define ETH_P_8021AD 0x88A8 /* 802.1ad Service VLAN		*/

// Network parsing
#define MAX_VLAN_DEPTH 2 /* Max nested VLAN tags to parse (Q-in-Q support) */

// BPF Ring Buffer
#define RINGBUF_SIZE_PKT (1024 * 1024) /* 1MB for DNS packet capture */
#define RINGBUF_SIZE_LOG (256 * 1024)  /* 256KB for BPF logs */

// Logging
#define LOG_TIMESTAMP_LEN 16 /* Buffer size for timestamp string "HH:MM:SS\0" */
