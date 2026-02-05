#ifndef __BPF_LOG_H
#define __BPF_LOG_H

enum log_level {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERR = 3,
};

struct log_event {
    int level;
    char msg[128];
};

// ==========================================
// kernel space
// ==========================================
#if defined(__VMLINUX_H__) || defined(__BPF_HELPERS__)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb_log SEC(".maps");

    #define bpf_log_base(lvl, fmt, ...) \
        ({ \
            struct log_event* __e; \
            __e = bpf_ringbuf_reserve(&rb_log, sizeof(*__e), 0); \
            if (__e) { \
                __e->level = lvl; \
                __u64 __args[] = { 0, ##__VA_ARGS__ }; \
                bpf_snprintf( \
                    __e->msg, \
                    sizeof(__e->msg), \
                    fmt, \
                    &__args[1], \
                    sizeof(__args) - sizeof(__u64) \
                ); \
                bpf_ringbuf_submit(__e, 0); \
            } \
        })

    #define bpf_debug(fmt, ...) bpf_log_base(LOG_DEBUG, fmt, ##__VA_ARGS__)
    #define bpf_info(fmt, ...) bpf_log_base(LOG_INFO, fmt, ##__VA_ARGS__)
    #define bpf_warn(fmt, ...) bpf_log_base(LOG_WARN, fmt, ##__VA_ARGS__)
    #define bpf_err(fmt, ...) bpf_log_base(LOG_ERR, fmt, ##__VA_ARGS__)

// ==========================================
// user space
// ==========================================
#else

    #include <stdbool.h>
    #include <stdio.h>
    #include <time.h>

struct log_options {
    enum log_level min_level;
    bool show_timestamp;
    bool use_color;
};

    // color macro
    #define COL_RESET "\033[0m"
    #define COL_RED "\033[1;31m"
    #define COL_YELLOW "\033[1;33m"
    #define COL_GREEN "\033[1;32m"
    #define COL_GRAY "\033[1;30m"

static inline int print_bpf_log(void* ctx, void* data, size_t len) {
    struct log_event* e = (struct log_event*)data;
    struct log_options* opts = (struct log_options*)ctx;

    // default config
    static struct log_options default_opts = { LOG_DEBUG, true, true };
    if (!opts)
        opts = &default_opts;

    if (e->level < (int)opts->min_level)
        return 0;

    // handle color
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

    // timestamp
    char time_buf[32] = "";
    if (opts->show_timestamp) {
        time_t rawtime;
        time(&rawtime);
        struct tm* ti = localtime(&rawtime);
        strftime(time_buf, sizeof(time_buf), "[%H:%M:%S] ", ti);
    }

    // print out
    // TODO: Concurrency is not safe here
    printf("%s%s[%-5s]%s %s\n", time_buf, color, lvl_str, reset, e->msg);
    return 0;
}

    // make clangd happy
    #define bpf_debug(fmt, ...)
    #define bpf_info(fmt, ...)
    #define bpf_warn(fmt, ...)
    #define bpf_err(fmt, ...)

#endif
#endif
