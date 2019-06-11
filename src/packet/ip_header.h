#pragma once

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "udp_header.h"

#define PROTOCOL_UDP 0x11
#define TTL 200

typedef struct ip_header {
	uint8_t header_length : 4;	// Internet header length (4 bits)
	uint8_t version : 4;		// Version (4 bits)
	uint8_t tos;				// Type of service
	uint16_t length;			// Total length
	uint16_t identification;	// Identification
	uint16_t frag_params;		// Fragmentation parameters
	uint8_t ttl;				// Time to live
	uint8_t next_protocol;		// Protocol of the next layer
	uint16_t checksum;			// Header checksum
	uint8_t src_addr[4];		// Source address
	uint8_t dst_addr[4];		// Destination address
} ip_header;

ip_header create_ip_header(size_t data_size, const uint8_t src_addr[4], const uint8_t dst_addr[4]);


