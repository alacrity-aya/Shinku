#pragma once

#include <common/types.h>
#include <stdio.h>

int handle_packet(void* ctx, void* data, size_t len);

// Testable versions of internal functions
int calculate_hash_strict_impl(const uint8_t* packet, int offset, int max_len, uint32_t* out_hash);
int flatten_name_impl(const uint8_t* packet, int offset, int max_len, uint8_t* dest, int dest_max);

static int process_dns_packet(uint8_t* data, uint32_t len);
