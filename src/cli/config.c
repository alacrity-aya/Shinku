// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "config.h"
#include "constants.h"
#include <argp.h>
#include <stdlib.h>
#include <string.h>

const char* argp_program_version = "dns-cache 0.1";
const char doc[] = "DNS cache";

static const struct argp_option opts[] = {
    { "interface", 'i', "IFACE", 0, "Network interface to attach (default: lo)", 0 },
    { "log-level", 'l', "LEVEL", 0, "Log level: debug, info, warn, error (default: info)", 0 },
    { "arena-pages", 'a', "PAGES", 0, "Arena size in pages (default: 1024 = 4MB)", 0 },
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
                argp_error(
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
                argp_error(state, "Invalid arena-pages: '%s' (range: 1-1048576)", arg);
            }
            env->arena_pages = (uint32_t)pages;
            break;
        }
        case ARGP_KEY_ARG:
            argp_usage(state);
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

int parse_args(int argc, char** argv, struct env* env) {
    // set default value
    env->interface = "lo";
    env->log_level = LOG_INFO;
    env->arena_pages = ARENA_DEFAULT_PAGES;
    return argp_parse(&argp, argc, argv, 0, NULL, env);
}
