// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file constants.h
 * @brief System-wide constants and magic numbers.
 *
 * This header defines all compile-time constants used across the DNS cache
 * system, including DNS protocol constants, BPF configuration, and tunables.
 */

/* ============================================================================
 * XDP/TC Action Codes (BPF context only)
 * ============================================================================ */

#ifdef __VMLINUX_H__
    /** @defgroup xdp_actions XDP Action Codes
     *  @brief Return values for XDP programs.
     *  @{
     */
    #define XDP_DROP 0     /**< Drop packet silently */
    #define XDP_ABORTED 1  /**< Drop packet with tracepoint */
    #define XDP_PASS 2     /**< Pass to normal network stack */
    #define XDP_TX 3       /**< Transmit from same interface */
    #define XDP_REDIRECT 4 /**< Redirect to another interface or CPUMAP */
    /** @} */

    /** @defgroup tc_actions TC Action Codes
     *  @brief Return values for TC (Traffic Control) programs.
     *  @{
     */
    #define TC_ACT_UNSPEC (-1)  /**< Unspecified action */
    #define TC_ACT_OK 0         /**< Continue processing */
    #define TC_ACT_RECLASSIFY 1 /**< Reclassify packet */
    #define TC_ACT_SHOT 2       /**< Drop packet */
    #define TC_ACT_PIPE 3       /**< Continue to next filter */
    #define TC_ACT_STOLEN 4     /**< Packet consumed by filter */
    #define TC_ACT_QUEUED 5     /**< Packet queued */
    #define TC_ACT_REPEAT 6     /**< Repeat classification */
    #define TC_ACT_REDIRECT 7   /**< Redirect packet */
/** @} */
#endif

/* ============================================================================
 * DNS Protocol Constants
 * ============================================================================ */

/** @defgroup dns_protocol DNS Protocol Constants
 *  @brief Standard DNS protocol values.
 *  @{
 */
#define DNS_PORT 53                  /**< Standard DNS port number */
#define MAX_DNS_NAME_LEN 255         /**< Maximum DNS name length (RFC 1035) */
#define MAX_DNS_CAPTURE_LEN 1024     /**< Maximum captured DNS packet size */
#define MAX_DNS_LABEL_ITERATIONS 100 /**< Max iterations for DNS name parsing (BPF verifier) */
/** @} */

/** @defgroup dns_flags DNS Header Flags
 *  @brief DNS header flag bits (host byte order).
 *  @{
 */
#define DNS_FLAG_QR 0x8000    /**< Query/Response bit (1=response) */
#define DNS_FLAG_TC 0x0200    /**< Truncated bit */
#define DNS_RCODE_MASK 0x000F /**< Response code mask */
#define DNS_RCODE_NOERROR 0   /**< No error condition */
#define DNS_RCODE_NXDOMAIN 3  /**< Name does not exist */
/** @} */

/** @defgroup dns_types DNS Resource Record Types
 *  @brief DNS RR type codes (RFC 1035, RFC 3596).
 *  @{
 */
#define DNS_TYPE_A 1     /**< IPv4 Address */
#define DNS_TYPE_NS 2    /**< Authoritative Name Server */
#define DNS_TYPE_CNAME 5 /**< Canonical Name for an alias */
#define DNS_TYPE_SOA 6   /**< Start of a zone of authority */
#define DNS_TYPE_PTR 12  /**< Domain name pointer (Reverse DNS) */
#define DNS_TYPE_MX 15   /**< Mail exchange */
#define DNS_TYPE_TXT 16  /**< Text strings */
#define DNS_TYPE_AAAA 28 /**< IPv6 Address */
#define DNS_TYPE_SRV 33  /**< Server selection */
/** @} */

/** @defgroup negative_cache Negative Cache TTL Limits
 *  @brief TTL boundaries for negative cache entries (RFC 2308).
 *  @{
 */
#define NEGATIVE_TTL_MIN 5   /**< Minimum negative cache TTL (seconds) */
#define NEGATIVE_TTL_MAX 600 /**< Maximum negative cache TTL (seconds) */
/** @} */

/* ============================================================================
 * FNV-1a Hash Constants
 * ============================================================================ */

/** @defgroup fnv_hash FNV-1a Hash Constants
 *  @brief Constants for 32-bit FNV-1a hash algorithm.
 *  @{
 */
#define FNV_OFFSET_BASIS_32 2166136261UL /**< FNV-1a initial hash value */
#define FNV_PRIME_32 16777619UL          /**< FNV-1a prime multiplier */
/** @} */

/* ============================================================================
 * Network Protocol Constants (BPF context only)
 * ============================================================================ */

#ifdef __VMLINUX_H__
    /** @defgroup eth_types Ethernet Protocol Types
     *  @brief Ethernet frame type codes.
     *  @{
     */
    #define ETH_P_8021Q 0x8100  /**< 802.1Q VLAN tag */
    #define ETH_P_IP 0x0800     /**< IPv4 */
    #define ETH_P_8021AD 0x88A8 /**< 802.1ad Q-in-Q */
/** @} */
#endif

/** @brief Maximum nested VLAN tags to parse (Q-in-Q support) */
#define MAX_VLAN_DEPTH 2

/* ============================================================================
 * BPF Configuration
 * ============================================================================ */

/** @defgroup bpf_ringbuf BPF Ring Buffer Sizes
 *  @brief Ring buffer sizes for BPF-to-userspace communication.
 *  @{
 */
#define RINGBUF_SIZE_PKT (1024 * 1024) /**< 1MB for DNS packet capture */
#define RINGBUF_SIZE_LOG (256 * 1024)  /**< 256KB for BPF logs */
/** @} */

/** @defgroup bpf_arena BPF Arena Configuration
 *  @brief Memory arena configuration for shared BPF/userspace cache.
 *  @{
 */
#define ARENA_ENTRY_SIZE 512        /**< Max traditional DNS UDP payload */
#define ARENA_DEFAULT_PAGES 2112    /**< Default: 2112 pages (~8.25MB) */
#define CACHE_MAP_MAX_ENTRIES 16384 /**< Max entries in cache_map */
#define CACHE_FREQ_ROWS 4
/** @} */

/* ============================================================================
 * EDNS0 Constants
 * ============================================================================ */

/** @defgroup edns0 EDNS0 Constants
 *  @brief Extension mechanisms for DNS (RFC 6891, RFC 7871).
 *  @{
 */
#define DNS_TYPE_OPT 41      /**< OPT pseudo-RR (RFC 6891) */
#define EDNS0_OPT_CODE_ECS 8 /**< EDNS Client Subnet (RFC 7871) */
/** @} */

#ifndef SHINKU_ECS_ENABLED
    #define SHINKU_ECS_ENABLED 0
#endif

/* ============================================================================
 * Logging Constants
 * ============================================================================ */

/** @brief Buffer size for timestamp string "HH:MM:SS\0" */
#define LOG_TIMESTAMP_LEN 16
