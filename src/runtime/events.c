// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0

/**
 * @file events.c
 * @brief Event bus implementation.
 *
 * This file implements the publish/subscribe event bus for inter-module
 * communication. See events.h for API documentation.
 */

#include "runtime/events.h"

#include <string.h>

void shinku_events_init(struct shinku_event_bus* bus) {
    if (!bus)
        return;
    memset(bus, 0, sizeof(*bus));
}

int shinku_events_subscribe(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    shinku_event_handler_fn handler,
    void* user_ctx
) {
    if (!bus || !handler)
        return -1;
    if ((unsigned int)type >= SHINKU_EVENT_MAX)
        return -1;

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    if (slot->count >= SHINKU_EVENT_MAX_SUBSCRIBERS)
        return -1;

    slot->subscribers[slot->count].handler = handler;
    slot->subscribers[slot->count].user_ctx = user_ctx;
    slot->count++;
    return 0;
}

int shinku_events_unsubscribe(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    shinku_event_handler_fn handler,
    void* user_ctx
) {
    if (!bus || !handler)
        return -1;
    if ((unsigned int)type >= SHINKU_EVENT_MAX)
        return -1;

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    for (uint8_t i = 0; i < slot->count; i++) {
        if (slot->subscribers[i].handler == handler && slot->subscribers[i].user_ctx == user_ctx) {
            /* Shift remaining subscribers down to fill the gap */
            for (uint8_t j = (uint8_t)(i + 1); j < slot->count; j++) {
                slot->subscribers[j - 1] = slot->subscribers[j];
            }
            slot->count--;
            return 0;
        }
    }

    return -1;
}

void shinku_events_publish(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    const void* payload
) {
    if (!bus)
        return;
    if ((unsigned int)type >= SHINKU_EVENT_MAX)
        return;

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    for (uint8_t i = 0; i < slot->count; i++) {
        shinku_event_handler_fn handler = slot->subscribers[i].handler;
        if (handler) {
            handler(type, payload, slot->subscribers[i].user_ctx);
        }
    }
}
