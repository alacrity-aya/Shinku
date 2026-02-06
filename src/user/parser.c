#include "parser.h"

int handle_packet(void* ctx, void* data, [[maybe_unused]] size_t len) {
    struct dns_event* e = data;

    printf("[Packet] Captured DNS Response! Len=%d Timestamp=%llu\n", e->len, e->timestamp);

    // TODO: parse dns here
    // TODO: write into bpf_arena

    return 0;
}
