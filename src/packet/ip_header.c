#include "ip_header.h"

static uint16_t calculate_checksum(ip_header *ih) {
	uint8_t i;
	uint16_t *raw_data = (uint16_t *)ih;
	uint32_t sum = 0;

	for (i = 0; i < 10; i++) {
		if (i == 5) {
			continue;
		}
		sum += raw_data[i];
	}

	while ((sum & 0xffff0000) != 0) {
		sum = (((sum & 0xffff0000) >> 0x10) + (sum & 0x0000ffff));
	}

	return (uint16_t)sum;
}

ip_header create_ip_header(size_t data_size, const uint8_t src_addr[4], const uint8_t dst_addr[4]) {
	ip_header ih;
	ih.version = 4;
	ih.header_length = sizeof(ip_header) / 4;
	ih.length = htons(sizeof(udp_header) + sizeof(ip_header) + sizeof(custom_header) + data_size);
	ih.tos = 0;
	ih.frag_params = ntohs(0x4000);
	ih.ttl = TTL;
	ih.next_protocol = PROTOCOL_UDP;
	memcpy(ih.src_addr, src_addr, 4);
	memcpy(ih.dst_addr, dst_addr, 4);
	ih.checksum = ntohs(calculate_checksum(&ih));

	return ih;
}
