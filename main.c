#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "ipv4.h"

int main() {
    int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

    if (sock == -1) {
        fprintf(stderr, "socket failed: %d\n", errno);
        return 1;
    }

    while (1) {
        uint8_t packet_buf[IPV4_PACKET_BUFFER_LENGTH];
        ssize_t bytes_read = read(sock, packet_buf, sizeof packet_buf);

        if (bytes_read == -1) {
            fprintf(stderr, "recvfrom failed: %d\n", errno);
            continue;
        }

        if (bytes_read < sizeof packet_buf) {
            fprintf(stderr, "packet buffer wasn't filled\n");
            continue;
        }

        struct ipv4_headers headers = ipv4_headers_from(packet_buf);

        ipv4_headers_println_out(&headers);
    }

    close(sock);

    return 0;
}