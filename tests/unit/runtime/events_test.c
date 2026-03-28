// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

#include "events.h"

#include <assert.h>
#include <stdio.h>

struct counter_ctx {
    int set_count;
    int clear_count;
};

static void
event_counter_handler(enum shinku_event_type type, const void* payload, void* user_ctx) {
    (void)payload;
    struct counter_ctx* ctx = user_ctx;
    if (!ctx)
        return;

    if (type == SHINKU_EVENT_DEGRADED_REASON_SET)
        ctx->set_count++;
    if (type == SHINKU_EVENT_DEGRADED_REASON_CLEAR)
        ctx->clear_count++;
}

static void test_duplicate_subscription_rejected(void) {
    struct shinku_event_bus bus;
    shinku_events_init(&bus);

    struct counter_ctx ctx = { 0 };
    int first = shinku_events_subscribe(
        &bus,
        SHINKU_EVENT_DEGRADED_REASON_SET,
        event_counter_handler,
        &ctx
    );
    int second = shinku_events_subscribe(
        &bus,
        SHINKU_EVENT_DEGRADED_REASON_SET,
        event_counter_handler,
        &ctx
    );

    assert(first == 0);
    assert(second == -1);

    shinku_events_destroy(&bus);
}

static void test_publish_with_local_snapshot(void) {
    struct shinku_event_bus bus;
    shinku_events_init(&bus);

    struct counter_ctx ctx = { 0 };
    int err = shinku_events_subscribe(
        &bus,
        SHINKU_EVENT_DEGRADED_REASON_SET,
        event_counter_handler,
        &ctx
    );
    assert(err == 0);

    struct shinku_event_degraded_payload payload = {
        .reason_flag = 1,
        .flags_after = 1,
    };
    shinku_events_publish(&bus, SHINKU_EVENT_DEGRADED_REASON_SET, &payload);

    assert(ctx.set_count == 1);
    assert(ctx.clear_count == 0);

    shinku_events_destroy(&bus);
}

int main(void) {
    test_duplicate_subscription_rejected();
    test_publish_with_local_snapshot();

    printf("Event Bus Test: PASS\n");
    return 0;
}
