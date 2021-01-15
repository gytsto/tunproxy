#include "packet_parser.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>

#include "log.h"

char const *get_protocol_name(uint8_t protocol_id)
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

bool is_ip_v4_valid(char const *ip)
{
    struct sockaddr_in sa = { 0 };
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

bool is_ip_v6_valid(char const *ip)
{
    struct sockaddr_in sa = { 0 };
    int result = inet_pton(AF_INET6, ip, &(sa.sin_addr));
    return result != 0;
}

bool is_packet_udp(uint8_t const *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->protocol == 17);
}

bool is_packet_tcp(uint8_t const *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->protocol == 6);
}

bool is_packet_ipv4(uint8_t const *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->version == 4);
}

bool is_packet_ipv6(uint8_t const *buf)
{
    struct iphdr *iph = (struct iphdr *)buf;
    return (iph != NULL && iph->version == 6);
}

void print_ip_header(uint8_t const *buf, int size)
{
    struct iphdr *iph = (struct iphdr *)buf;
    struct sockaddr_in src = { 0 };
    struct sockaddr_in dst = { 0 };

    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr;

    log_info("IP version      : %u", iph->version);
    log_info("Protocol        : %s", get_protocol_name(iph->protocol));
    log_info("Packet size     : %u", ntohs(iph->tot_len));
    log_info("Buffer size     : %d", size);
    log_info("Source IP       : %s", inet_ntoa(src.sin_addr));
    log_info("Destination IP  : %s", inet_ntoa(dst.sin_addr));
}
