#include "packet_parser.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>

#include "log.h"

char const *get_protocol_name(unsigned int protocol_id)
{
    switch (protocol_id) {
        case 1:
            return "icmp";
        case 17:
            return "udp";
        case 6:
            return "tcp";
        default:
            return "not supported";
    }
}

bool is_ip_valid(char *ip)
{
    struct sockaddr_in sa = { 0 };
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

bool is_packet_udp(unsigned char *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->protocol == 17);
}

bool is_packet_tcp(unsigned char *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->protocol == 6);
}

bool is_packet_ipv4(unsigned char *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->version == 4);
}

bool is_packet_ipv6(unsigned char *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->version == 6);
}

void print_ip_header(unsigned char *buf, int size)
{
    struct iphdr *iph = (struct iphdr *)buf;
    struct sockaddr_in src = { 0 };
    struct sockaddr_in dst = { 0 };

    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr;

    log_trace("IP version      : %u", iph->version);
    log_trace("Protocol        : %s", get_protocol_name(iph->protocol));
    log_trace("Packet size     : %u", ntohs(iph->tot_len));
    log_trace("Buffer size     : %d", size);
    log_trace("Source IP       : %s", inet_ntoa(src.sin_addr));
    log_trace("Destination IP  : %s", inet_ntoa(dst.sin_addr));
}
