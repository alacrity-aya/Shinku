// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "obs_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define OBS_HTTP_BUF_SIZE 4096

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
        send(fd, header, (size_t)hdr_len, 0);
    send(fd, body, body_len, 0);
}

static void render_metrics(char* out, size_t out_size, struct obs_metrics* m) {
    uint64_t cache_hit =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_CACHE_HIT].value, memory_order_relaxed);
    uint64_t cache_miss =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_CACHE_MISS].value, memory_order_relaxed);
    uint64_t cache_expired =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_CACHE_EXPIRED].value, memory_order_relaxed);
    uint64_t gen_mismatch =
        atomic_load_explicit(
            &m->bpf_counters[OBS_BPF_CACHE_GEN_MISMATCH].value,
            memory_order_relaxed
        );
    uint64_t seq_conflict =
        atomic_load_explicit(
            &m->bpf_counters[OBS_BPF_CACHE_SEQ_CONFLICT].value,
            memory_order_relaxed
        );
    uint64_t xdp_tx =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_XDP_TX].value, memory_order_relaxed);
    uint64_t ring_drop =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_TC_RINGBUF_DROP].value, memory_order_relaxed);
    uint64_t tc_capture =
        atomic_load_explicit(&m->bpf_counters[OBS_BPF_TC_CAPTURE].value, memory_order_relaxed);

    uint64_t parser_reject =
        atomic_load_explicit(&m->parser_reject_total.value, memory_order_relaxed);
    uint64_t cache_insert =
        atomic_load_explicit(&m->cache_insert_total.value, memory_order_relaxed);
    uint64_t cache_insert_fail =
        atomic_load_explicit(&m->cache_insert_fail_total.value, memory_order_relaxed);
    uint64_t cleanup_removed =
        atomic_load_explicit(&m->cleanup_removed_total.value, memory_order_relaxed);
    uint64_t rb_poll_err =
        atomic_load_explicit(&m->rb_pkt_poll_error_total.value, memory_order_relaxed);
    uint64_t reject_not_response =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_NOT_RESPONSE].value, memory_order_relaxed);
    uint64_t reject_bad_qdcount =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_BAD_QDCOUNT].value, memory_order_relaxed);
    uint64_t reject_tc =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_TC].value, memory_order_relaxed);
    uint64_t reject_rcode =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_RCODE].value, memory_order_relaxed);
    uint64_t reject_no_answer =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_NO_ANSWER].value, memory_order_relaxed);
    uint64_t reject_malformed_name =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_MALFORMED_NAME].value, memory_order_relaxed);
    uint64_t reject_malformed_question =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_MALFORMED_QUESTION].value, memory_order_relaxed);
    uint64_t reject_malformed_rr =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_MALFORMED_RR].value, memory_order_relaxed);
    uint64_t reject_unsupported_rtype =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_UNSUPPORTED_RTYPE].value, memory_order_relaxed);
    uint64_t reject_cname_no_terminal =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_CNAME_NO_TERMINAL].value, memory_order_relaxed);
    uint64_t reject_bad_ecs =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_BAD_ECS].value, memory_order_relaxed);
    uint64_t reject_bad_ttl =
        atomic_load_explicit(&m->parser_reject_by_reason[OBS_REJECT_BAD_TTL].value, memory_order_relaxed);
    uint32_t sample_mask = m->cfg.bpf_sample_mask;

    snprintf(
        out,
        out_size,
        "# HELP shinku_bpf_sample_mask BPF sampling mask, event counted when (rand32 & mask)==0\n"
        "# TYPE shinku_bpf_sample_mask gauge\n"
        "shinku_bpf_sample_mask %u\n"
        "# HELP shinku_cache_hit_total Number of sampled XDP cache hits\n"
        "# TYPE shinku_cache_hit_total counter\n"
        "shinku_cache_hit_total %llu\n"
        "# HELP shinku_cache_miss_total Number of sampled XDP cache misses\n"
        "# TYPE shinku_cache_miss_total counter\n"
        "shinku_cache_miss_total %llu\n"
        "# HELP shinku_cache_expired_hit_total Number of sampled expired cache entries encountered in XDP\n"
        "# TYPE shinku_cache_expired_hit_total counter\n"
        "shinku_cache_expired_hit_total %llu\n"
        "# HELP shinku_cache_gen_mismatch_total Number of sampled generation mismatches\n"
        "# TYPE shinku_cache_gen_mismatch_total counter\n"
        "shinku_cache_gen_mismatch_total %llu\n"
        "# HELP shinku_cache_seq_conflict_total Number of sampled seqlock conflicts\n"
        "# TYPE shinku_cache_seq_conflict_total counter\n"
        "shinku_cache_seq_conflict_total %llu\n"
        "# HELP shinku_xdp_tx_total Number of sampled XDP_TX responses\n"
        "# TYPE shinku_xdp_tx_total counter\n"
        "shinku_xdp_tx_total %llu\n"
        "# HELP shinku_tc_capture_total Number of sampled TC-captured DNS responses\n"
        "# TYPE shinku_tc_capture_total counter\n"
        "shinku_tc_capture_total %llu\n"
        "# HELP shinku_tc_ringbuf_drop_total Number of sampled TC ringbuf reservation drops\n"
        "# TYPE shinku_tc_ringbuf_drop_total counter\n"
        "shinku_tc_ringbuf_drop_total %llu\n"
        "# HELP shinku_parser_reject_total Number of parser rejections\n"
        "# TYPE shinku_parser_reject_total counter\n"
        "shinku_parser_reject_total %llu\n"
        "# HELP shinku_parser_reject_reason_total Parser reject counters by reason\n"
        "# TYPE shinku_parser_reject_reason_total counter\n"
        "shinku_parser_reject_reason_total{reason=\"not_response\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"bad_qdcount\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"tc\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"rcode\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"no_answer\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"malformed_name\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"malformed_question\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"malformed_rr\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"unsupported_rtype\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"cname_no_terminal\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"bad_ecs\"} %llu\n"
        "shinku_parser_reject_reason_total{reason=\"bad_ttl\"} %llu\n"
        "# HELP shinku_cache_insert_total Successful cache inserts\n"
        "# TYPE shinku_cache_insert_total counter\n"
        "shinku_cache_insert_total %llu\n"
        "# HELP shinku_cache_insert_fail_total Failed cache inserts\n"
        "# TYPE shinku_cache_insert_fail_total counter\n"
        "shinku_cache_insert_fail_total %llu\n"
        "# HELP shinku_cache_cleanup_removed_total Expired entries removed by cleanup\n"
        "# TYPE shinku_cache_cleanup_removed_total counter\n"
        "shinku_cache_cleanup_removed_total %llu\n"
        "# HELP shinku_rb_pkt_poll_error_total Packet ring poll errors\n"
        "# TYPE shinku_rb_pkt_poll_error_total counter\n"
        "shinku_rb_pkt_poll_error_total %llu\n",
        sample_mask,
        (unsigned long long)cache_hit,
        (unsigned long long)cache_miss,
        (unsigned long long)cache_expired,
        (unsigned long long)gen_mismatch,
        (unsigned long long)seq_conflict,
        (unsigned long long)xdp_tx,
        (unsigned long long)tc_capture,
        (unsigned long long)ring_drop,
        (unsigned long long)parser_reject,
        (unsigned long long)reject_not_response,
        (unsigned long long)reject_bad_qdcount,
        (unsigned long long)reject_tc,
        (unsigned long long)reject_rcode,
        (unsigned long long)reject_no_answer,
        (unsigned long long)reject_malformed_name,
        (unsigned long long)reject_malformed_question,
        (unsigned long long)reject_malformed_rr,
        (unsigned long long)reject_unsupported_rtype,
        (unsigned long long)reject_cname_no_terminal,
        (unsigned long long)reject_bad_ecs,
        (unsigned long long)reject_bad_ttl,
        (unsigned long long)cache_insert,
        (unsigned long long)cache_insert_fail,
        (unsigned long long)cleanup_removed,
        (unsigned long long)rb_poll_err
    );
}

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
        render_metrics(body, sizeof(body), srv->metrics);
        write_response(client_fd, "200 OK", "text/plain; version=0.0.4; charset=utf-8", body);
        return;
    }

    write_response(client_fd, "404 Not Found", "text/plain; charset=utf-8", "not_found\n");
}

static void* obs_http_thread(void* arg) {
    struct obs_http_server* srv = arg;
    while (atomic_load_explicit(&srv->running, memory_order_acquire)) {
        int client_fd = accept(srv->listen_fd, NULL, NULL);
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
    atomic_bool* bpf_ready
) {
    memset(srv, 0, sizeof(*srv));
    srv->port = port;
    srv->metrics = metrics;
    srv->bpf_ready = bpf_ready;

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

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }

    srv->listen_fd = fd;
    atomic_store_explicit(&srv->running, true, memory_order_release);

    int err = pthread_create(&srv->thread, NULL, obs_http_thread, srv);
    if (err != 0) {
        close(fd);
        srv->listen_fd = -1;
        atomic_store_explicit(&srv->running, false, memory_order_release);
        return -1;
    }

    return 0;
}

void obs_http_stop(struct obs_http_server* srv) {
    if (!atomic_load_explicit(&srv->running, memory_order_acquire))
        return;

    atomic_store_explicit(&srv->running, false, memory_order_release);
    shutdown(srv->listen_fd, SHUT_RDWR);
    close(srv->listen_fd);
    srv->listen_fd = -1;

    pthread_join(srv->thread, NULL);
}
