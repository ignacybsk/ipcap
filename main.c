#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <stdint.h>
#include <sys/socket.h>

#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

#include "ipv4.h"

int main(int argc, char* const argv[]) {
    const char help_text[] =
        "usage: ipcap [options...]\n"
        "-p <proto> filter by protocol\n"
        "-s <addr> filter by source address\n"
        "-d <addr> filter by destination address\n"
        "-i <name> bind to a specific network interface\n"
        "-h print this message\n";

    int opt = 0;

    char* opt_proto = NULL;
    char* opt_if_name = NULL;

    uint32_t opt_src = 0;
    uint32_t opt_dst = 0;

    while ((opt = getopt(argc, argv, "i:p:s:d:h")) != -1) {
        switch (opt) {
        case 'p':
            opt_proto = optarg;
            break;
        case 's':
            opt_src = ipv4_string_to_address(optarg);
            break;
        case 'd':
            opt_dst = ipv4_string_to_address(optarg);
            break;
        case 'i':
            opt_if_name = optarg;
            break;
        case 'h':
            printf(help_text);
            return 0;
        default:
            return 1;
        }
    }

    int opt_proto_num = 0;

    if (opt_proto) {
        struct protoent* ent = getprotobyname(opt_proto);

        if (!ent) {
            fprintf(stderr, "unrecognized protocol '%s'\n", opt_proto);
            return 1;
        }

        opt_proto_num = ent->p_proto;
    }

    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    if (opt_if_name) {
        unsigned int if_index = if_nametoindex(opt_if_name);

        if (!if_index) {
            perror("if_nametoindex");
            close(sock);
            return 1;
        }

        struct sockaddr_ll ll = {
            .sll_ifindex = if_index,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_family = AF_PACKET,
        };

        if (bind(sock, (struct sockaddr*)&ll, sizeof ll) == -1) {
            perror("bind");
            close(sock);
            return 1;
        }
    }

    printf("listening %s %s\n", opt_if_name, opt_proto);

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

        if (opt_src && opt_src != headers.source_address)
            continue;

        if (opt_dst && opt_dst != headers.destination_address)
            continue;

        ipv4_headers_print_to(stdout, &headers);
    }

    close(sock);

    return 0;
}
