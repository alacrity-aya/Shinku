// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include "bpf_log.h"
#include <stdint.h>

/**
 * @file config.h
 * @brief CLI argument parsing and configuration.
 *
 * This header defines the configuration structure and parsing functions
 * for the Shinku DNS cache daemon command-line interface.
 */

/**
 * @struct env
 * @brief Runtime configuration parsed from command-line arguments.
 *
 * This structure holds all configurable parameters for the DNS cache
 * daemon, including network interface selection, logging options,
 * arena memory sizing, and observability settings.
 */
struct env {
    const char* interface; /**< Network interface to attach XDP program */
    enum log_level log_level; /**< Minimum log level for output */
    uint32_t arena_pages; /**< Number of pages for BPF arena memory */
    uint32_t cleanup_interval; /**< Cache cleanup interval in seconds */
    uint32_t metrics_port; /**< Prometheus/health HTTP port (localhost only) */
    uint32_t obs_enabled; /**< Userspace observability switch (0=disabled) */
    uint32_t obs_bpf_enabled; /**< BPF counter collection switch (0=disabled) */
    uint32_t obs_bpf_sample_mask; /**< BPF sampling mask: rand32 & mask == 0 */
};

/**
 * @brief Parse command-line arguments into configuration.
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @param env Output: parsed configuration structure.
 * @return 0 on success, negative on error.
 *
 * Parses all supported command-line options and populates the env
 * structure with defaults for unspecified options.
 */
int config_parse_args(int argc, char** argv, struct env* env);

/**
 * @brief Legacy alias for config_parse_args.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param env Output configuration.
 * @return 0 on success, negative on error.
 * @deprecated Use config_parse_args() instead.
 */
int parse_args(int argc, char** argv, struct env* env);
