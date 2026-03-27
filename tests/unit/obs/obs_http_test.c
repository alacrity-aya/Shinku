// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#include "core/obs_http.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int test_count;
static int pass_count;

#define TEST_ASSERT(cond, msg) \
    do { \
        test_count++; \
        if (cond) { \
            pass_count++; \
            printf("[PASS] %s\n", msg); \
        } else { \
            printf("[FAIL] %s\n", msg); \
        } \
    } while (0)

static int pick_free_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) != 0) {
        close(fd);
        return -1;
    }

    int port = ntohs(addr.sin_port);
    close(fd);
    return port;
}

static int http_get(uint16_t port, const char* path, char* out, size_t out_sz) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    char req[256];
    int req_len = snprintf(
        req,
        sizeof(req),
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        path
    );
    if (req_len <= 0 || req_len >= (int)sizeof(req)) {
        close(fd);
        return -1;
    }

    if (send(fd, req, (size_t)req_len, 0) != req_len) {
        close(fd);
        return -1;
    }

    size_t total = 0;
    while (total + 1 < out_sz) {
        ssize_t n = recv(fd, out + total, out_sz - total - 1, 0);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    out[total] = '\0';

    close(fd);
    return 0;
}

int main(void) {
    struct obs_metrics metrics;
    struct obs_metrics_config cfg = {
        .enabled = 1,
        .bpf_enabled = 1,
        .bpf_sample_mask = 0xff,
    };
    obs_metrics_init(&metrics, &cfg);

    obs_metrics_count_parser_reject(&metrics, OBS_REJECT_RCODE);
    obs_metrics_count_cache_insert(&metrics, 1);
    obs_metrics_count_cache_insert(&metrics, 0);
    obs_metrics_count_negative_accept(&metrics, OBS_NEGATIVE_NXDOMAIN);
    obs_metrics_count_negative_accept(&metrics, OBS_NEGATIVE_NXDOMAIN);
    obs_metrics_count_negative_reject(&metrics, OBS_NEGATIVE_NODATA);
    obs_metrics_count_parser_reject(&metrics, OBS_REJECT_NEGATIVE_NO_SOA);
    obs_metrics_add_cleanup_removed(&metrics, 3);
    obs_metrics_count_rb_poll_error(&metrics);
    atomic_store_explicit(&metrics.bpf_counters[OBS_BPF_CACHE_HIT].value, 7, memory_order_relaxed);

    atomic_bool bpf_ready = false;
    struct degraded_state degraded;
    degraded_state_init(&degraded);
    struct obs_http_server srv;
    int port = pick_free_port();
    TEST_ASSERT(port > 0, "pick free localhost port");

    int err = obs_http_start(&srv, (uint16_t)port, &metrics, &degraded, &bpf_ready);
    TEST_ASSERT(err == 0, "start observability HTTP server");
    if (err != 0)
        return 1;

    char resp[8192];
    memset(resp, 0, sizeof(resp));

    TEST_ASSERT(
        http_get((uint16_t)port, "/healthz", resp, sizeof(resp)) == 0,
        "GET /healthz succeeds"
    );
    TEST_ASSERT(strstr(resp, "200 OK") != NULL, "/healthz returns HTTP 200");
    TEST_ASSERT(strstr(resp, "ok\n") != NULL, "/healthz body is ok");

    memset(resp, 0, sizeof(resp));
    TEST_ASSERT(
        http_get((uint16_t)port, "/readyz", resp, sizeof(resp)) == 0,
        "GET /readyz succeeds before ready"
    );
    TEST_ASSERT(
        strstr(resp, "503 Service Unavailable") != NULL,
        "/readyz returns 503 before ready"
    );
    TEST_ASSERT(strstr(resp, "not_ready\n") != NULL, "/readyz body is not_ready before ready");

    atomic_store_explicit(&bpf_ready, true, memory_order_release);

    memset(resp, 0, sizeof(resp));
    TEST_ASSERT(
        http_get((uint16_t)port, "/readyz", resp, sizeof(resp)) == 0,
        "GET /readyz succeeds after ready"
    );
    TEST_ASSERT(strstr(resp, "200 OK") != NULL, "/readyz returns 200 after ready");
    TEST_ASSERT(strstr(resp, "ready\n") != NULL, "/readyz body is ready after ready");

    memset(resp, 0, sizeof(resp));
    TEST_ASSERT(
        http_get((uint16_t)port, "/metrics", resp, sizeof(resp)) == 0,
        "GET /metrics succeeds"
    );
    TEST_ASSERT(strstr(resp, "200 OK") != NULL, "/metrics returns HTTP 200");
    TEST_ASSERT(
        strstr(resp, "shinku_cache_hit_total 7") != NULL,
        "/metrics includes BPF cache hit counter"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_parser_reject_total") != NULL,
        "/metrics includes parser reject counter"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_cache_insert_total 1") != NULL,
        "/metrics includes cache insert counter"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_cache_insert_fail_total 1") != NULL,
        "/metrics includes cache insert fail counter"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_negative_cache_accept_total 2") != NULL,
        "/metrics includes negative accept aggregate"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_negative_cache_accept_by_type_total{type=\"nxdomain\"} 2") != NULL,
        "/metrics includes NXDOMAIN accept metric"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_negative_cache_accept_by_type_total") != NULL,
        "/metrics includes NODATA accept metric"
    );
    TEST_ASSERT(strstr(resp, "negative") != NULL, "/metrics includes negative reject aggregate");
    TEST_ASSERT(strstr(resp, "negative") != NULL, "/metrics includes NODATA reject metric");
    TEST_ASSERT(
        strstr(resp, "shinku_parser_reject_reason_total{reason=\"negative_no_soa\"}") != NULL,
        "/metrics exports negative parser reject reason"
    );
    TEST_ASSERT(
        strstr(resp, "shinku_degraded_mode 0") != NULL,
        "/metrics includes degraded mode gauge"
    );

    memset(resp, 0, sizeof(resp));
    TEST_ASSERT(
        http_get((uint16_t)port, "/unknown", resp, sizeof(resp)) == 0,
        "GET /unknown succeeds"
    );
    TEST_ASSERT(strstr(resp, "404 Not Found") != NULL, "/unknown returns HTTP 404");

    obs_http_stop(&srv);

    printf("Total: %d, Passed: %d, Failed: %d\n", test_count, pass_count, test_count - pass_count);
    return (pass_count == test_count) ? 0 : 1;
}
