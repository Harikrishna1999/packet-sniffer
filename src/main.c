#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

#include "parser.h"

int main(int argc, char *argv[])
{
    int sock_raw;
    unsigned char buffer[65536];
    int filter = 0;  // default: all

    // CLI argument parsing
    if (argc > 1)
    {
        if (strcmp(argv[1], "--tcp") == 0)
            filter = 1;
        else if (strcmp(argv[1], "--udp") == 0)
            filter = 2;
        else if (strcmp(argv[1], "--icmp") == 0)
            filter = 3;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock_raw < 0)
    {
        perror("Socket Error");
        return 1;
    }

    printf("Packet Sniffer Started...\n");

    while (1)
    {
        int data_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0, NULL, NULL);

        if (data_size < 0)
        {
            perror("Recv Error");
            return 1;
        }

        process_packet(buffer, data_size, filter);
    }

    close(sock_raw);
    return 0;
}
