// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

/**
 * @file obs_http.c
 * @brief Implementation of HTTP server for Prometheus metrics export.
 *
 * This file implements a minimal HTTP server that exposes:
 *   - GET /metrics : Prometheus-formatted metrics
 *   - GET /healthz : Health check endpoint (always 200 OK)
 *   - GET /readyz  : Readiness check (200 when BPF ready, 503 otherwise)
 *
 * The server runs in a dedicated thread and uses blocking I/O.
 */
#include "obs_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define OBS_HTTP_BUF_SIZE 8192

static int send_all(int fd, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

/**
 * @brief Write an HTTP response to a socket.
 * @param fd Socket file descriptor.
 * @param status HTTP status line (e.g., "200 OK").
 * @param content_type MIME type for Content-Type header.
 * @param body Response body content.
 */
static void write_response(int fd, const char* status, const char* content_type, const char* body) {
    char header[512];
    size_t body_len = strlen(body);
    int hdr_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status,
        content_type,
        body_len
    );
    if (hdr_len > 0)
        send_all(fd, header, (size_t)hdr_len);
    send_all(fd, body, body_len);
}

static void
render_metrics(char* out, size_t out_size, struct obs_metrics* m, struct degraded_state* degraded) {
    size_t remaining = out_size;
    int truncated = 0;

#define APPEND(...) \
    do { \
        if (remaining == 0) { \
            truncated = 1; \
            break; \
        } \
        int _n = snprintf(out, remaining, __VA_ARGS__); \
        if (_n > 0) { \
            size_t _w = ((size_t)_n < remaining) ? (size_t)_n : remaining; \
            out += _w; \
            remaining -= _w; \
            if ((size_t)_n >= _w) \
                truncated = 1; \
        } \
    } while (0)

#define LOAD(field) atomic_load_explicit(&(field), memory_order_relaxed)

#define GAUGE(name, help, val, fmt) \
    APPEND("# HELP " name " " help "\n# TYPE " name " gauge\n" name " %" fmt "\n", val)

#define COUNTER(name, help, val, fmt) \
    APPEND("# HELP " name " " help "\n# TYPE " name " counter\n" name " %" fmt "\n", val)

    uint32_t flags = degraded ? degraded_get_reason_flags(degraded) : 0;

    GAUGE(
        "shinku_degraded_mode",
        "1 if any degraded mode reason is active",
        flags ? 1u : 0u,
        PRIu32
    );

    APPEND("# HELP shinku_degraded_reason_active Active degraded reasons by type\n");
    APPEND("# TYPE shinku_degraded_reason_active gauge\n");
#define DEGRADED_ACTIVE(reason_str, flag) \
    APPEND( \
        "shinku_degraded_reason_active{reason=\"" reason_str "\"} %u\n", \
        (flags & (flag)) ? 1u : 0u \
    )

    DEGRADED_ACTIVE("userspace_lag", DEGRADED_REASON_USERSPACE_LAG);
    DEGRADED_ACTIVE("cleanup_failure", DEGRADED_REASON_CLEANUP_FAILURE);
    DEGRADED_ACTIVE("startup_attach_retry", DEGRADED_REASON_STARTUP_ATTACH_RETRY);
    DEGRADED_ACTIVE("cache_map_update_failure", DEGRADED_REASON_CACHE_MAP_UPDATE_FAILURE);
#undef DEGRADED_ACTIVE

    COUNTER(
        "shinku_degraded_transitions_total",
        "Number of degraded mode transitions",
        degraded ? LOAD(degraded->transitions_total.value) : 0,
        PRIu64
    );

    APPEND(
        "# HELP shinku_degraded_reason_set_total Number of times each degraded reason became active\n"
    );
    APPEND("# TYPE shinku_degraded_reason_set_total counter\n");
#define DEGRADED_SET(reason_str, idx) \
    APPEND( \
        "shinku_degraded_reason_set_total{reason=\"" reason_str "\"} %" PRIu64 "\n", \
        degraded ? LOAD(degraded->reason_set_total[idx].value) : 0 \
    )

    DEGRADED_SET("userspace_lag", 0);
    DEGRADED_SET("cleanup_failure", 1);
    DEGRADED_SET("startup_attach_retry", 2);
    DEGRADED_SET("cache_map_update_failure", 3);
#undef DEGRADED_SET

    GAUGE(
        "shinku_bpf_sample_mask",
        "BPF sampling mask, event counted when (rand32 & mask)==0",
        m->cfg.bpf_sample_mask,
        PRIu32
    );

#define BPF_COUNTER(metric, help, enum_val) \
    COUNTER(metric, help, LOAD(m->bpf_counters[enum_val].value), PRIu64)

    BPF_COUNTER("shinku_cache_hit_total", "Number of sampled XDP cache hits", OBS_BPF_CACHE_HIT);
    BPF_COUNTER(
        "shinku_cache_miss_total",
        "Number of sampled XDP cache misses",
        OBS_BPF_CACHE_MISS
    );
    BPF_COUNTER(
        "shinku_cache_expired_hit_total",
        "Number of sampled expired cache entries encountered in XDP",
        OBS_BPF_CACHE_EXPIRED
    );
    BPF_COUNTER(
        "shinku_cache_gen_mismatch_total",
        "Number of sampled generation mismatches",
        OBS_BPF_CACHE_GEN_MISMATCH
    );
    BPF_COUNTER(
        "shinku_cache_seq_conflict_total",
        "Number of sampled seqlock conflicts",
        OBS_BPF_CACHE_SEQ_CONFLICT
    );
    BPF_COUNTER("shinku_xdp_tx_total", "Number of sampled XDP_TX responses", OBS_BPF_XDP_TX);
    BPF_COUNTER(
        "shinku_tc_capture_total",
        "Number of sampled TC-captured DNS responses",
        OBS_BPF_TC_CAPTURE
    );
    BPF_COUNTER(
        "shinku_tc_ringbuf_drop_total",
        "Number of sampled TC ringbuf reservation drops",
        OBS_BPF_TC_RINGBUF_DROP
    );
#undef BPF_COUNTER

    COUNTER(
        "shinku_parser_reject_total",
        "Number of parser rejections",
        LOAD(m->parser_reject_total.value),
        PRIu64
    );

    APPEND("# HELP shinku_parser_reject_reason_total Parser reject counters by reason\n");
    APPEND("# TYPE shinku_parser_reject_reason_total counter\n");
#define REJECT_REASON(reason_str, enum_val) \
    APPEND( \
        "shinku_parser_reject_reason_total{reason=\"" reason_str "\"} %" PRIu64 "\n", \
        LOAD(m->parser_reject_by_reason[enum_val].value) \
    )

    REJECT_REASON("not_response", OBS_REJECT_NOT_RESPONSE);
    REJECT_REASON("bad_qdcount", OBS_REJECT_BAD_QDCOUNT);
    REJECT_REASON("tc", OBS_REJECT_TC);
    REJECT_REASON("rcode", OBS_REJECT_RCODE);
    REJECT_REASON("no_answer", OBS_REJECT_NO_ANSWER);
    REJECT_REASON("malformed_name", OBS_REJECT_MALFORMED_NAME);
    REJECT_REASON("malformed_question", OBS_REJECT_MALFORMED_QUESTION);
    REJECT_REASON("malformed_rr", OBS_REJECT_MALFORMED_RR);
    REJECT_REASON("unsupported_rtype", OBS_REJECT_UNSUPPORTED_RTYPE);
    REJECT_REASON("ipv6_ignored", OBS_REJECT_IPV6_IGNORED);
    REJECT_REASON("cname_no_terminal_a", OBS_REJECT_CNAME_NO_TERMINAL_A);
    REJECT_REASON("cname_ipv6_only_terminal", OBS_REJECT_CNAME_IPV6_ONLY_TERMINAL);
    REJECT_REASON("bad_ecs", OBS_REJECT_BAD_ECS);
    REJECT_REASON("bad_ttl", OBS_REJECT_BAD_TTL);
    REJECT_REASON("negative_no_soa", OBS_REJECT_NEGATIVE_NO_SOA);
    REJECT_REASON("negative_bad_policy", OBS_REJECT_NEGATIVE_BAD_POLICY);
#undef REJECT_REASON

    COUNTER(
        "shinku_cache_insert_total",
        "Successful cache inserts",
        LOAD(m->cache_insert_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_insert_fail_total",
        "Failed cache inserts",
        LOAD(m->cache_insert_fail_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_attempt_total",
        "Cache admission attempts",
        LOAD(m->cache_admission_attempt_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_accept_total",
        "Accepted cache admission decisions",
        LOAD(m->cache_admission_accept_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_reject_total",
        "Rejected cache admission decisions",
        LOAD(m->cache_admission_reject_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_reject_recent_total",
        "Rejected by recent-insert dampening",
        LOAD(m->cache_admission_reject_recent_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_reject_ttl_total",
        "Rejected by minimum TTL policy",
        LOAD(m->cache_admission_reject_ttl_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_admission_reject_freq_total",
        "Rejected by frequency compare policy",
        LOAD(m->cache_admission_reject_freq_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_eviction_total",
        "Total evictions caused by slot reuse",
        LOAD(m->cache_eviction_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_eviction_hot_total",
        "Evictions where victim slot was hot",
        LOAD(m->cache_eviction_hot_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_cache_eviction_cold_total",
        "Evictions where victim slot was cold",
        LOAD(m->cache_eviction_cold_total.value),
        PRIu64
    );
    GAUGE(
        "shinku_cache_hot_segment_size",
        "Current number of hot segment entries",
        LOAD(m->cache_hot_segment_size.value),
        PRIu64
    );
    GAUGE(
        "shinku_cache_cold_segment_size",
        "Current number of cold segment entries",
        LOAD(m->cache_cold_segment_size.value),
        PRIu64
    );
    COUNTER(
        "shinku_negative_cache_accept_total",
        "Accepted negative cache inserts (all types)",
        LOAD(m->negative_cache_accept_total[OBS_NEGATIVE_NXDOMAIN].value)
            + LOAD(m->negative_cache_accept_total[OBS_NEGATIVE_NODATA].value),
        PRIu64
    );
    APPEND(
        "# HELP shinku_negative_cache_accept_by_type_total Accepted negative cache inserts by type\n"
    );
    APPEND("# TYPE shinku_negative_cache_accept_by_type_total counter\n");
    APPEND(
        "shinku_negative_cache_accept_by_type_total{type=\"nxdomain\"} %" PRIu64 "\n",
        LOAD(m->negative_cache_accept_total[OBS_NEGATIVE_NXDOMAIN].value)
    );
    APPEND(
        "shinku_negative_cache_accept_by_type_total{type=\"nodata\"} %" PRIu64 "\n",
        LOAD(m->negative_cache_accept_total[OBS_NEGATIVE_NODATA].value)
    );

    COUNTER(
        "shinku_negative_cache_reject_total",
        "Rejected negative cache inserts (all types)",
        LOAD(m->negative_cache_reject_total[OBS_NEGATIVE_NXDOMAIN].value)
            + LOAD(m->negative_cache_reject_total[OBS_NEGATIVE_NODATA].value),
        PRIu64
    );
    APPEND(
        "# HELP shinku_negative_cache_reject_by_type_total Rejected negative cache inserts by type\n"
    );
    APPEND("# TYPE shinku_negative_cache_reject_by_type_total counter\n");
    APPEND(
        "shinku_negative_cache_reject_by_type_total{type=\"nxdomain\"} %" PRIu64 "\n",
        LOAD(m->negative_cache_reject_total[OBS_NEGATIVE_NXDOMAIN].value)
    );
    APPEND(
        "shinku_negative_cache_reject_by_type_total{type=\"nodata\"} %" PRIu64 "\n",
        LOAD(m->negative_cache_reject_total[OBS_NEGATIVE_NODATA].value)
    );

    COUNTER(
        "shinku_cache_cleanup_removed_total",
        "Expired entries removed by cleanup",
        LOAD(m->cleanup_removed_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_rb_pkt_poll_error_total",
        "Packet ring poll errors",
        LOAD(m->rb_pkt_poll_error_total.value),
        PRIu64
    );
    COUNTER(
        "shinku_metrics_truncated_total",
        "Number of times metrics output exceeded response buffer",
        LOAD(m->metrics_truncated_total.value),
        PRIu64
    );

    if (truncated) {
        obs_metrics_count_metrics_truncated(m);
    }

#undef APPEND
#undef LOAD
#undef GAUGE
#undef COUNTER
}

/**
 * @brief Handle a single HTTP client request.
 * @param client_fd Client socket file descriptor.
 * @param srv HTTP server context.
 *
 * Routes requests to appropriate handlers:
 *   - GET /healthz -> 200 OK
 *   - GET /readyz -> 200 or 503 based on BPF ready state
 *   - GET /metrics -> Prometheus metrics
 */
static void handle_client(int client_fd, struct obs_http_server* srv) {
    char req[1024];
    ssize_t n = recv(client_fd, req, sizeof(req) - 1, 0);
    if (n <= 0)
        return;
    req[n] = '\0';

    if (strncmp(req, "GET /healthz", sizeof("GET /healthz") - 1) == 0) {
        write_response(client_fd, "200 OK", "text/plain; charset=utf-8", "ok\n");
        return;
    }

    if (strncmp(req, "GET /readyz", sizeof("GET /readyz") - 1) == 0) {
        if (srv->bpf_ready && atomic_load_explicit(srv->bpf_ready, memory_order_acquire))
            write_response(client_fd, "200 OK", "text/plain; charset=utf-8", "ready\n");
        else
            write_response(
                client_fd,
                "503 Service Unavailable",
                "text/plain; charset=utf-8",
                "not_ready\n"
            );
        return;
    }

    if (strncmp(req, "GET /metrics", sizeof("GET /metrics") - 1) == 0) {
        char body[OBS_HTTP_BUF_SIZE];
        render_metrics(body, sizeof(body), srv->metrics, srv->degraded);
        write_response(client_fd, "200 OK", "text/plain; version=0.0.4; charset=utf-8", body);
        return;
    }

    write_response(client_fd, "404 Not Found", "text/plain; charset=utf-8", "not_found\n");
}

/**
 * @brief Main loop for the HTTP server thread.
 * @param arg HTTP server context pointer.
 * @return NULL on thread exit.
 *
 * Accepts connections in a loop and dispatches to handle_client().
 * Thread exits when srv->running is cleared.
 */
static void* obs_http_thread(void* arg) {
    struct obs_http_server* srv = arg;
    while (atomic_load_explicit(&srv->running, memory_order_acquire)) {
        int listen_fd = atomic_load_explicit(&srv->listen_fd, memory_order_acquire);
        if (listen_fd < 0)
            break;

        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            if (!atomic_load_explicit(&srv->running, memory_order_acquire))
                break;
            continue;
        }

        handle_client(client_fd, srv);
        close(client_fd);
    }

    return NULL;
}

int obs_http_start(
    struct obs_http_server* srv,
    uint16_t port,
    struct obs_metrics* metrics,
    struct degraded_state* degraded,
    atomic_bool* bpf_ready
) {
    memset(srv, 0, sizeof(*srv));
    srv->port = port;
    srv->metrics = metrics;
    srv->degraded = degraded;
    srv->bpf_ready = bpf_ready;
    atomic_store_explicit(&srv->listen_fd, -1, memory_order_relaxed);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (port == 0) {
        struct sockaddr_in bound_addr;
        socklen_t bound_len = sizeof(bound_addr);
        memset(&bound_addr, 0, sizeof(bound_addr));
        if (getsockname(fd, (struct sockaddr*)&bound_addr, &bound_len) == 0)
            srv->port = ntohs(bound_addr.sin_port);
    }

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    atomic_store_explicit(&srv->listen_fd, fd, memory_order_release);
    atomic_store_explicit(&srv->running, true, memory_order_release);

    int err = pthread_create(&srv->thread, NULL, obs_http_thread, srv);
    if (err != 0) {
        close(fd);
        atomic_store_explicit(&srv->listen_fd, -1, memory_order_release);
        atomic_store_explicit(&srv->running, false, memory_order_release);
        return -1;
    }

    return 0;
}

void obs_http_stop(struct obs_http_server* srv) {
    if (!atomic_load_explicit(&srv->running, memory_order_acquire))
        return;

    atomic_store_explicit(&srv->running, false, memory_order_release);
    int listen_fd = atomic_exchange_explicit(&srv->listen_fd, -1, memory_order_acq_rel);
    if (listen_fd >= 0) {
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
    }

    pthread_join(srv->thread, NULL);
}
