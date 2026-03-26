#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "parser.h"

void process_packet(unsigned char* buffer, int size)
{
    // Skip Ethernet header (14 bytes)
    struct iphdr *ip = (struct iphdr*)(buffer + 14);

    struct sockaddr_in source, dest;

    source.sin_addr.s_addr = ip->saddr;
    dest.sin_addr.s_addr = ip->daddr;

    printf("\n=========== Packet ===========\n");
    printf("Source IP      : %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP : %s\n", inet_ntoa(dest.sin_addr));

    int ip_header_len = ip->ihl * 4;

    if (ip->protocol == 6) // TCP
    {
        struct tcphdr *tcp = (struct tcphdr*)(buffer + 14 + ip_header_len);

        printf("Protocol       : TCP\n");
        printf("Source Port    : %u\n", ntohs(tcp->source));
        printf("Destination Port: %u\n", ntohs(tcp->dest));
    }
    else if (ip->protocol == 17) // UDP
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
    else
    {
        printf("Protocol       : Other (%d)\n", ip->protocol);
    }

    printf("Packet Size    : %d bytes\n", size);
}
