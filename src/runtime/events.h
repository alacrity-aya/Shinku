// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
#pragma once

#include <pthread.h>
#include <stdint.h>

/**
 * @file events.h
 * @brief Event bus system for decoupled module communication.
 *
 * This module implements a publish/subscribe event bus pattern that allows
 * modules to communicate without direct dependencies. Events are published
 * to topics and delivered to all registered subscribers.
 *
 * Design goals:
 *   - Decouple modules (e.g., degraded_mode and obs_metrics)
 *   - Support multiple subscribers per event type
 *   - Zero allocations (all state pre-allocated)
 *   - Simple synchronous delivery model
 *
 * @note This implementation is NOT thread-safe. Callers must provide
 *       external synchronization if used from multiple threads.
 */

/** @brief Maximum subscribers per event topic */
#define SHINKU_EVENT_MAX_SUBSCRIBERS 8

/**
 * @enum shinku_event_type
 * @brief Event type identifiers for the event bus.
 */
enum shinku_event_type {
    SHINKU_EVENT_DEGRADED_REASON_SET = 0, /**< Degraded reason flag was set */
    SHINKU_EVENT_DEGRADED_REASON_CLEAR = 1, /**< Degraded reason flag was cleared */
    SHINKU_EVENT_MAX = 2, /**< Sentinel: number of event types */
};

/**
 * @struct shinku_event_degraded_payload
 * @brief Payload for degraded mode events.
 *
 * Delivered when degraded mode reason flags change.
 */
struct shinku_event_degraded_payload {
    uint32_t reason_flag; /**< The reason flag that was set or cleared */
    uint32_t flags_after; /**< Complete reason flags after the change */
};

/**
 * @typedef shinku_event_handler_fn
 * @brief Event handler callback function type.
 *
 * @param type The event type that was published.
 * @param payload Event-specific payload data (may be NULL).
 * @param user_ctx User context provided during subscription.
 */
typedef void (*shinku_event_handler_fn)(
    enum shinku_event_type type,
    const void* payload,
    void* user_ctx
);

/**
 * @struct shinku_event_subscriber
 * @brief Represents a single subscriber to an event topic.
 */
struct shinku_event_subscriber {
    shinku_event_handler_fn handler; /**< Callback function */
    void* user_ctx; /**< User context passed to handler */
};

/**
 * @struct shinku_event_topic_slot
 * @brief Subscriber list for a single event type.
 */
struct shinku_event_topic_slot {
    struct shinku_event_subscriber
        subscribers[SHINKU_EVENT_MAX_SUBSCRIBERS]; /**< Subscriber array */
    uint8_t count; /**< Current subscriber count */
};

/**
 * @struct shinku_event_bus
 * @brief Complete event bus state.
 *
 * Contains subscriber lists for all event types. Pre-allocated
 * to avoid runtime memory allocation.
 */
struct shinku_event_bus {
    struct shinku_event_topic_slot topics[SHINKU_EVENT_MAX]; /**< Topic slots */
    pthread_mutex_t lock;
    uint8_t lock_ready;
};

/**
 * @brief Initialize an event bus structure.
 * @param bus Pointer to event bus to initialize (may be NULL).
 *
 * Zeros all fields, preparing the bus for use.
 *
 * @note Safe to call with NULL pointer (no-op).
 */
void shinku_events_init(struct shinku_event_bus* bus);

void shinku_events_destroy(struct shinku_event_bus* bus);

/**
 * @brief Subscribe to an event type.
 * @param bus Event bus to subscribe on.
 * @param type Event type to subscribe to.
 * @param handler Callback function to invoke on event.
 * @param user_ctx User context passed to handler (may be NULL).
 * @return 0 on success, -1 on error.
 *
 * Errors:
 *   - bus or handler is NULL
 *   - type is out of range
 *   - subscriber limit reached (SHINKU_EVENT_MAX_SUBSCRIBERS)
 *
 * @note Subscribers are called in subscription order during publish.
 * @note Same handler+user_ctx pair can only be subscribed once per topic.
 */
int shinku_events_subscribe(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    shinku_event_handler_fn handler,
    void* user_ctx
);

/**
 * @brief Unsubscribe from an event type.
 * @param bus Event bus to unsubscribe from.
 * @param type Event type to unsubscribe from.
 * @param handler Callback function previously subscribed.
 * @param user_ctx User context that was used during subscription.
 * @return 0 on success, -1 on error.
 *
 * Errors:
 *   - bus or handler is NULL
 *   - type is out of range
 *   - handler+user_ctx pair not found in subscribers
 *
 * @note Both handler and user_ctx must match the original subscription.
 */
int shinku_events_unsubscribe(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    shinku_event_handler_fn handler,
    void* user_ctx
);

/**
 * @brief Publish an event to all subscribers.
 * @param bus Event bus to publish on.
 * @param type Event type to publish.
 * @param payload Event-specific payload (may be NULL).
 *
 * Delivers the event to all registered subscribers in subscription order.
 * Delivery is synchronous: all handlers complete before this function returns.
 *
 * @note Safe to call with NULL bus (no-op).
 * @note Safe to call with out-of-range type (no-op).
 * @note Handlers are called even if payload is NULL.
 */
void shinku_events_publish(
    struct shinku_event_bus* bus,
    enum shinku_event_type type,
    const void* payload
);
