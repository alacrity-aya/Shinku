// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config.h"
#include "constants.h"
#include <argp.h>
#include <stdlib.h>
#include <string.h>

const char* argp_program_version = "shinku 0.1";
const char doc[] = "DNS cache";

static const struct argp_option opts[] = {
    { "interface", 'i', "IFACE", 0, "Network interface to attach (default: lo)", 0 },
    { "log-level", 'l', "LEVEL", 0, "Log level: debug, info, warn, error (default: info)", 0 },
    { "arena-pages", 'a', "PAGES", 0, "Arena size in pages (default: 1024 = 4MB)", 0 },
    { "cleanup-interval", 'c', "SECS", 0, "Cache cleanup interval in seconds (default: 10)", 0 },
    { "metrics-port", 'm', "PORT", 0, "Observability HTTP port on localhost (default: 9095)", 0 },
    { "obs",
      'o',
      "0|1",
      0,
      "Enable userspace observability counters + HTTP endpoints (default: 1)",
      0 },
    { "obs-bpf", 'p', "0|1", 0, "Enable BPF-side counter sampling (default: 0)", 0 },
    { "obs-bpf-mask",
      'k',
      "MASK",
      0,
      "BPF sample mask: count when (bpf_get_prandom_u32() & MASK)==0 (default: 0xff)",
      0 },
    { NULL, 0, NULL, 0, NULL, 0 }
};

static int parse_log_level_str(const char* str) {
    if (strcasecmp(str, "debug") == 0)
        return LOG_DEBUG;
    if (strcasecmp(str, "info") == 0)
        return LOG_INFO;
    if (strcasecmp(str, "warn") == 0)
        return LOG_WARN;
    if (strcasecmp(str, "error") == 0)
        return LOG_ERR;
    return -1;
}

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    struct env* env = state->input;

    switch (key) {
        case 'i':
            env->interface = arg;
            break;
        case 'l': {
            int lvl = parse_log_level_str(arg);
            if (lvl == -1) {
                argp_error( // NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid log level: '%s'. Supported: debug, info, warn, error",
                    arg
                );
            }
            env->log_level = (enum log_level)lvl;
            break;
        }
        case 'a': {
            unsigned long pages = strtoul(arg, NULL, 0);
            if (pages == 0 || pages > 1048576) {
                argp_error( // NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid arena-pages: '%s' (range: 1-1048576)",
                    arg
                );
            }
            env->arena_pages = (uint32_t)pages;
            break;
        }
        case 'c': {
            unsigned long secs = strtoul(arg, NULL, 0);
            if (secs == 0 || secs > 86400) {
                argp_error(// NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid cleanup-interval: '%s' (range: 1-86400 seconds)",
                    arg
                );
            }
            env->cleanup_interval = (uint32_t)secs;
            break;
        }
        case 'm': {
            unsigned long port = strtoul(arg, NULL, 0);
            if (port == 0 || port > 65535) {
                argp_error(// NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid metrics-port: '%s' (range: 1-65535)",
                    arg
                );
            }
            env->metrics_port = (uint32_t)port;
            break;
        }
        case 'o': {
            unsigned long enabled = strtoul(arg, NULL, 0);
            if (enabled > 1) {
                argp_error( // NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid obs: '%s' (must be 0 or 1)",
                    arg
                ); // NOLINT(concurrency-mt-unsafe)
            }
            env->obs_enabled = (uint32_t)enabled;
            break;
        }
        case 'p': {
            unsigned long enabled = strtoul(arg, NULL, 0);
            if (enabled > 1) {
                argp_error( // NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid obs-bpf: '%s' (must be 0 or 1)",
                    arg
                );
            }
            env->obs_bpf_enabled = (uint32_t)enabled;
            break;
        }
        case 'k': {
            unsigned long mask = strtoul(arg, NULL, 0);
            if (mask > 0xffffffffUL) {
                argp_error( // NOLINT(concurrency-mt-unsafe)
                    state,
                    "Invalid obs-bpf-mask: '%s' (must fit uint32)",
                    arg
                );
            }
            env->obs_bpf_sample_mask = (uint32_t)mask;
            break;
        }
        case ARGP_KEY_ARG:
            argp_usage(state); // NOLINT(concurrency-mt-unsafe)
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_opt,
    .doc = doc,
};

int config_parse_args(int argc, char** argv, struct env* env) {
    // set default value
    env->interface = "lo";
    env->log_level = LOG_INFO;
    env->arena_pages = ARENA_DEFAULT_PAGES;
    env->cleanup_interval = 10; /* Default: 10 seconds */
    env->metrics_port = 9095;
    env->obs_enabled = 1;
    env->obs_bpf_enabled = 0;
    env->obs_bpf_sample_mask = 0xff;
    return argp_parse(&argp, argc, argv, 0, NULL, env); // NOLINT(concurrency-mt-unsafe)
}
