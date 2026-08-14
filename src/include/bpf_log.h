// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

/**
 * @file bpf_log.h
 * @brief BPF logging infrastructure for debug and diagnostics.
 *
 * This header provides a unified logging interface that works in both
 * BPF (kernel) and userspace contexts. Log messages from BPF programs
 * are sent via ring buffer to userspace for display.
 *
 * Compile-time toggle: Set SHINKU_BPF_LOG_ENABLED=1 to enable BPF logging.
 */

#ifndef SHINKU_BPF_LOG_ENABLED
    #define SHINKU_BPF_LOG_ENABLED 0
#endif

/**
 * @enum log_level
 * @brief Log severity levels.
 */
enum log_level {
    LOG_DEBUG = 0, /**< Debug messages (verbose) */
    LOG_INFO = 1,  /**< Informational messages */
    LOG_WARN = 2,  /**< Warning messages */
    LOG_ERR = 3,   /**< Error messages */
};

/**
 * @struct log_event
 * @brief Log event structure sent from BPF to userspace.
 */
struct log_event {
    int level;     /**< Log level (from enum log_level) */
    char msg[128]; /**< Formatted log message */
};

/* ============================================================================
 * BPF (Kernel Space) Implementation
 * ============================================================================ */

#if defined(__VMLINUX_H__) || defined(__BPF_HELPERS__)

    #if SHINKU_BPF_LOG_ENABLED

/** @internal Ring buffer map for log events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} _rb_log SEC(".maps");

    /**
 * @brief Internal: Reserve ring buffer and format log message.
 * @param lvl Log level.
 * @param fmt Printf-style format string.
 * @param ... Format arguments.
 */
        #define bpf_log_base(lvl, fmt, ...) \
            ({ \
                struct log_event* __e; \
                __e = bpf_ringbuf_reserve(&_rb_log, sizeof(*__e), 0); \
                if (__e) { \
                    __e->level = lvl; \
                    __u64 __args[] = { 0, ##__VA_ARGS__, 0 }; \
                    bpf_snprintf(__e->msg, sizeof(__e->msg), fmt, &__args[1], sizeof(__args) - sizeof(__u64)); \
                    bpf_ringbuf_submit(__e, 0); \
                } \
            })

    #else
        #define bpf_log_base(lvl, fmt, ...) \
            do { \
            } while (0)
    #endif

/** @brief Log a debug message from BPF. */
    #define bpf_debug(fmt, ...) bpf_log_base(LOG_DEBUG, fmt, ##__VA_ARGS__)
/** @brief Log an info message from BPF. */
    #define bpf_info(fmt, ...) bpf_log_base(LOG_INFO, fmt, ##__VA_ARGS__)
/** @brief Log a warning message from BPF. */
    #define bpf_warn(fmt, ...) bpf_log_base(LOG_WARN, fmt, ##__VA_ARGS__)
/** @brief Log an error message from BPF. */
    #define bpf_err(fmt, ...) bpf_log_base(LOG_ERR, fmt, ##__VA_ARGS__)

/* ============================================================================
 * Userspace Implementation
 * ============================================================================ */
#else

    #include <stdbool.h>
    #include <stdio.h>
    #include <time.h>

/**
 * @struct log_options
 * @brief Configuration options for log output in userspace.
 */
struct log_options {
    enum log_level min_level; /**< Minimum level to display */
    bool show_timestamp;      /**< Include timestamp in output */
    bool use_color;           /**< Use ANSI color codes */
};

    /* ANSI color codes for log output */
    #define COL_RESET "\033[0m"     /**< Reset color */
    #define COL_RED "\033[1;31m"    /**< Red (error) */
    #define COL_YELLOW "\033[1;33m" /**< Yellow (warning) */
    #define COL_GREEN "\033[1;32m"  /**< Green (info) */
    #define COL_GRAY "\033[1;30m"   /**< Gray (debug) */

/**
 * @brief Print a BPF log event to stdout.
 * @param ctx Pointer to log_options structure (or NULL for defaults).
 * @param data Pointer to log_event structure.
 * @param len Length of data (unused, for callback signature compatibility).
 * @return Always returns 0.
 *
 * This function is used as a callback for ring_buffer__new() to process
 * log events from BPF programs.
 *
 * @note Not thread-safe for concurrent output to stdout.
 */
static inline int print_bpf_log(void* ctx, void* data, size_t _) {
    struct log_event* e = (struct log_event*)data;
    struct log_options* opts = (struct log_options*)ctx;

    /* Default configuration */
    static struct log_options default_opts = { LOG_DEBUG, true, true };
    if (!opts)
        opts = &default_opts;

    if (e->level < (int)opts->min_level)
        return 0;

    /* Handle color */
    const char* lvl_str = "UNK";
    const char* color = "";
    const char* reset = "";

    if (opts->use_color) {
        reset = COL_RESET;
        switch (e->level) {
            case LOG_DEBUG:
                lvl_str = "DEBUG";
                color = COL_GRAY;
                break;
            case LOG_INFO:
                lvl_str = "INFO";
                color = COL_GREEN;
                break;
            case LOG_WARN:
                lvl_str = "WARN";
                color = COL_YELLOW;
                break;
            case LOG_ERR:
                lvl_str = "ERROR";
                color = COL_RED;
                break;
        }
    } else {
        switch (e->level) {
            case LOG_DEBUG:
                lvl_str = "DEBUG";
                break;
            case LOG_INFO:
                lvl_str = "INFO";
                break;
            case LOG_WARN:
                lvl_str = "WARN";
                break;
            case LOG_ERR:
                lvl_str = "ERROR";
                break;
        }
    }

    /* Format timestamp */
    char time_buf[32] = "";
    if (opts->show_timestamp) {
        time_t rawtime;
        time(&rawtime);
        struct tm* ti = localtime(&rawtime);
        strftime(time_buf, sizeof(time_buf), "[%H:%M:%S] ", ti);
    }

    /* Print output */
    printf("%s%s[%-5s]%s %s\n", time_buf, color, lvl_str, reset, e->msg);
    return 0;
}

    /* Make clangd happy: define empty macros for userspace */
    #define bpf_debug(fmt, ...)
    #define bpf_info(fmt, ...)
    #define bpf_warn(fmt, ...)
    #define bpf_err(fmt, ...)

#endif
