#include "ipv4.h"

#include <netdb.h>
#include <stdint.h>
#include <stdio.h>

struct ipv4_headers ipv4_headers_from(const uint8_t buf[]) {
    struct ipv4_headers headers = {
        .version = buf[IPV4_VERSION_IDX] >> IPV4_VERSION_SHIFT,
        .ihl = buf[IPV4_IHL_IDX] & IPV4_IHL_MASK,
        .dscp = buf[IPV4_DSCP_IDX] >> IPV4_DSCP_SHIFT,
        .ecn = buf[IPV4_ECN_IDX] & IPV4_ECN_MASK,
        .total_length = (buf[IPV4_TOTALLENGTH_MSB_IDX] << 8) | buf[IPV4_TOTALLENGTH_LSB_IDX],
        .identification = (buf[IPV4_IDENTIFICATION_MSB_IDX] << 8) | buf[IPV4_IDENTIFICATION_LSB_IDX],
        .flags = buf[IPV4_FLAGS_IDX] >> IPV4_FLAGS_SHIFT,
        .fragment_offset = ((buf[IPV4_FRAGMENTOFFSET_MSB_IDX] & IPV4_FRAGMENTOFFSET_MSB_MASK) << 8) | buf[IPV4_FRAGMENTOFFSET_LSB_IDX],
        .time_to_live = buf[IPV4_TIMETOLIVE_IDX],
        .protocol = buf[IPV4_PROTOCOL_IDX],
        .header_checksum = (buf[IPV4_HEADERCHECKSUM_MSB_IDX] << 8) | buf[IPV4_HEADERCHECKSUM_LSB_IDX],
        .source_address = ipv4_address_from(buf, IPV4_SOURCEADDRESS_OFFSET, IPV4_SOURCEADDRESS_LENGTH),
        .destination_address = ipv4_address_from(buf, IPV4_DESTINATIONADDRESS_OFFSET, IPV4_DESTINATIONADDRESS_LENGTH),
    };

    return headers;
}

uint32_t ipv4_address_from(const uint8_t buf[], int offset, int length) {
    uint32_t address = 0;

    for (int i = 0; i < length; i++) {
        uint8_t address_byte = buf[offset + i];
        int shift_by = ((length - i) - 1) * 8;
        address |= (address_byte << shift_by);
    }

    return address;
}

int ipv4_data_size_from(struct ipv4_headers* headers) {
    return headers->total_length - IPV4_HEADER_SIZE;
}

int ipv4_is_packet_ipv4(uint8_t packet_msb) {
    return (packet_msb >> 4) == 4;
}

uint32_t ipv4_string_to_address(const char string[]) {
    int byte1, byte2, byte3, byte4;

    sscanf(string, "%3d.%3d.%3d.%3d", &byte1, &byte2, &byte3, &byte4);

    return (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte1;
}

void ipv4_address_to_string(uint32_t address, char string[]) {
    uint8_t byte1 = address >> 24;
    uint8_t byte2 = address >> 16;
    uint8_t byte3 = address >> 8;
    uint8_t byte4 = address;

    sprintf(string, "%d.%d.%d.%d", byte1, byte2, byte3, byte4);
}

void ipv4_headers_print_to(FILE* fd, struct ipv4_headers* headers) {
    char src_addr_str[IPV4_ADDRESS_STRING_LENGTH];
    ipv4_address_to_string(headers->source_address, src_addr_str);

    char dst_addr_str[IPV4_ADDRESS_STRING_LENGTH];
    ipv4_address_to_string(headers->destination_address, dst_addr_str);

    int data_size = ipv4_data_size_from(headers);

    struct protoent* p_ent = getprotobynumber(headers->protocol);
    char* protocol_name;

    if (p_ent) {
        protocol_name = p_ent->p_name;
    } else {
        protocol_name = "unrecognized";
    }

    const char* format = "%s %s -> %s  size=%d  ttl=%u  id=%u\n";

    fprintf(fd, format, protocol_name, src_addr_str, dst_addr_str, data_size, headers->time_to_live, headers->identification);
}
