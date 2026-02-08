#pragma once

#include <common/types.h>
#include <stdio.h>

int handle_packet(void* ctx, void* data, size_t len);

static int process_dns_packet(uint8_t* data, uint32_t len);
