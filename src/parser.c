#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "parser.h"

void process_packet(unsigned char* buffer, int size, int filter)
{
    struct iphdr *ip = (struct iphdr*)(buffer + 14);

    int ip_header_len = ip->ihl * 4;

    // Filtering logic
    if (filter == 1 && ip->protocol != 6) return;   // TCP
    if (filter == 2 && ip->protocol != 17) return;  // UDP
    if (filter == 3 && ip->protocol != 1) return;   // ICMP

    struct sockaddr_in source, dest;
    source.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;

    printf("\n=========== Packet ===========\n");
    printf("Source IP      : %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP : %s\n", inet_ntoa(dest.sin_addr));

    if (ip->protocol == 6)
    {
        struct tcphdr *tcp = (struct tcphdr*)(buffer + 14 + ip_header_len);

        printf("Protocol       : TCP\n");
        printf("Source Port    : %u\n", ntohs(tcp->source));
        printf("Destination Port: %u\n", ntohs(tcp->dest));
    }
    else if (ip->protocol == 17)
    {
        struct udphdr *udp = (struct udphdr*)(buffer + 14 + ip_header_len);

        printf("Protocol       : UDP\n");
        printf("Source Port    : %u\n", ntohs(udp->source));
        printf("Destination Port: %u\n", ntohs(udp->dest));
    }
    else if (ip->protocol == 1)
    {
        printf("Protocol       : ICMP\n");
    }

    printf("Packet Size    : %d bytes\n", size);
}
