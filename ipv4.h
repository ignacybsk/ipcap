#pragma once

#include <stdint.h>

#define IPV4_PACKET_BUFFER_LENGTH 19
#define IPV4_HEADER_SIZE 20

#define IPV4_VERSION_IDX 0
#define IPV4_VERSION_SHIFT 4

#define IPV4_IHL_IDX 0
#define IPV4_IHL_MASK 0b00001111

#define IPV4_DSCP_IDX 1
#define IPV4_DSCP_SHIFT 2

#define IPV4_ECN_IDX 1
#define IPV4_ECN_MASK 0b00000011

#define IPV4_TOTALLENGTH_MSB_IDX 2
#define IPV4_TOTALLENGTH_LSB_IDX 3

#define IPV4_IDENTIFICATION_MSB_IDX 4
#define IPV4_IDENTIFICATION_LSB_IDX 5

#define IPV4_FLAGS_IDX 6
#define IPV4_FLAGS_SHIFT 5

#define IPV4_FRAGMENTOFFSET_MSB_IDX 6
#define IPV4_FRAGMENTOFFSET_MSB_MASK 0b00011111
#define IPV4_FRAGMENTOFFSET_LSB_IDX 7

#define IPV4_TIMETOLIVE_IDX 8

#define IPV4_PROTOCOL_IDX 9

#define IPV4_HEADERCHECKSUM_MSB_IDX 10
#define IPV4_HEADERCHECKSUM_LSB_IDX 11

#define IPV4_SOURCEADDRESS_OFFSET 12
#define IPV4_SOURCEADDRESS_LENGTH 4

#define IPV4_DESTINATIONADDRESS_OFFSET 16
#define IPV4_DESTINATIONADDRESS_LENGTH 4

#define IPV4_ADDRESS_STRING_LENGTH 15

struct ipv4_headers {
    const uint8_t version;
    const uint8_t ihl;
    const uint8_t dscp;
    const uint8_t ecn;
    const uint16_t total_length;
    const uint16_t identification;
    const uint8_t flags;
    const uint16_t fragment_offset;
    const uint8_t time_to_live;
    const uint8_t protocol;
    const uint16_t header_checksum;
    const uint32_t source_address;
    const uint32_t destination_address;
};

struct ipv4_headers ipv4_headers_from(const uint8_t buf[]);
uint32_t ipv4_address_from(const uint8_t buf[], int offset, int length);
int ipv4_data_size_from(struct ipv4_headers* headers);
void ipv4_address_to_string(uint32_t address, char string[]);
void ipv4_headers_println_out(struct ipv4_headers* packet);