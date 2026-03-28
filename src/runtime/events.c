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
    if (pthread_mutex_init(&bus->lock, NULL) == 0)
        bus->lock_ready = 1;
}

void shinku_events_destroy(struct shinku_event_bus* bus) {
    if (!bus)
        return;
    if (bus->lock_ready) {
        pthread_mutex_destroy(&bus->lock);
        bus->lock_ready = 0;
    }
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

    if (bus->lock_ready)
        pthread_mutex_lock(&bus->lock);

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    if (slot->count >= SHINKU_EVENT_MAX_SUBSCRIBERS) {
        if (bus->lock_ready)
            pthread_mutex_unlock(&bus->lock);
        return -1;
    }

    for (uint8_t i = 0; i < slot->count; i++) {
        if (slot->subscribers[i].handler == handler && slot->subscribers[i].user_ctx == user_ctx) {
            if (bus->lock_ready)
                pthread_mutex_unlock(&bus->lock);
            return -1;
        }
    }

    slot->subscribers[slot->count].handler = handler;
    slot->subscribers[slot->count].user_ctx = user_ctx;
    slot->count++;

    if (bus->lock_ready)
        pthread_mutex_unlock(&bus->lock);

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

    if (bus->lock_ready)
        pthread_mutex_lock(&bus->lock);

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    for (uint8_t i = 0; i < slot->count; i++) {
        if (slot->subscribers[i].handler == handler && slot->subscribers[i].user_ctx == user_ctx) {
            /* Shift remaining subscribers down to fill the gap */
            for (uint8_t j = (uint8_t)(i + 1); j < slot->count; j++) {
                slot->subscribers[j - 1] = slot->subscribers[j];
            }
            slot->count--;
            if (bus->lock_ready)
                pthread_mutex_unlock(&bus->lock);
            return 0;
        }
    }

    if (bus->lock_ready)
        pthread_mutex_unlock(&bus->lock);

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

    struct shinku_event_subscriber local_subscribers[SHINKU_EVENT_MAX_SUBSCRIBERS];
    uint8_t local_count = 0;

    if (bus->lock_ready)
        pthread_mutex_lock(&bus->lock);

    struct shinku_event_topic_slot* slot = &bus->topics[type];
    local_count = slot->count;
    for (uint8_t i = 0; i < local_count; i++) {
        local_subscribers[i] = slot->subscribers[i];
    }

    if (bus->lock_ready)
        pthread_mutex_unlock(&bus->lock);

    for (uint8_t i = 0; i < local_count; i++) {
        shinku_event_handler_fn handler = local_subscribers[i].handler;
        if (handler) {
            handler(type, payload, local_subscribers[i].user_ctx);
        }
    }
}
