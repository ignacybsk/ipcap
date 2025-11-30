#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "ipv4.h"

int main(int argc, char* const argv[]) {
    int opt;

    char* opt_proto = NULL;

    uint32_t opt_src;
    uint32_t opt_dst;

    while ((opt = getopt(argc, argv, "p:s:d:")) != -1) {
        if (optarg) {
            opt == 'p' ? (opt_proto = optarg) : 0;
            opt == 's' ? (opt_src = ipv4_string_to_address(optarg)) : 0;
            opt == 'd' ? (opt_dst = ipv4_string_to_address(optarg)) : 0;
        }
    }

    int opt_proto_num;

    if (opt_proto) {
        struct protoent* ent = getprotobyname(opt_proto);

        if (!ent) {
            fprintf(stderr, "unrecognized protocol '%s'\n", argv[1]);
            return 1;
        }

        opt_proto_num = ent->p_proto;
    }

    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    while (1) {
        uint8_t packet_buf[IPV4_PACKET_BUFFER_SIZE];
        ssize_t bytes_read = read(sock, packet_buf, IPV4_PACKET_BUFFER_SIZE);

        if (bytes_read == -1) {
            perror("read");
            continue;
        }

        if (bytes_read < sizeof packet_buf) {
            fprintf(stderr, "packet buffer wasn't filled\n");
            continue;
        }

        if (!ipv4_is_packet_ipv4(packet_buf[0]))
            continue;

        struct ipv4_headers headers = ipv4_headers_from(packet_buf);

        if (opt_proto_num && headers.protocol != opt_proto_num)
            continue;

        if (opt_src) {
            if (opt_src != headers.source_address)
                continue;
        }

        if (opt_dst) {
            if (opt_dst != headers.destination_address)
                continue;
        }

        ipv4_headers_print_to(stdout, &headers);
    }

    close(sock);

    return 0;
}
