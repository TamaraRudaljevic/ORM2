#pragma once

#include <stdint.h>
#include <stdlib.h>
#include "custom_header.h"
#include "eth_header.h"
#include "ip_header.h"
#include "udp_header.h"


#define MAX_DATA_SIZE 1000
#define WINDOW_SIZE 10
#define TTL 200
#define MAX_RETRIES 50
#define WAKE_UP_TIMEOUT 2
#define PACKET_NO 1

#define SENDER_PORT 50050
#define RECEIVER_PORT 50055

#define TIMEOUT 1
#define SLEEP_TIMEOUT 10000

typedef struct packet {
	ethernet_header eth_h;
	ip_header ip_h;
	udp_header udp_h;
	custom_header cus_h;
	unsigned char data[MAX_DATA_SIZE];
} packet;

typedef struct headers {
	ethernet_header eth_h;
	ip_header ip_h;
	udp_header udp_h;
	custom_header cus_h;
} headers;

packet *create_packet(ethernet_header eh, ip_header ih, udp_header uh, custom_header ch, unsigned char *data, size_t len);

u_int16_t calculate_udp_checksum(unsigned char *p, size_t size);
