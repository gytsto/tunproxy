#ifndef __PACKET_PARSER_H__
#define __PACKET_PARSER_H__

#include <stdbool.h>

bool is_ip_valid(char *ip);
bool is_packet_udp(unsigned char *buf);
bool is_packet_tcp(unsigned char *buf);
bool is_packet_ipv4(unsigned char *buf);
bool is_packet_ipv6(unsigned char *buf);
void print_ip_header(unsigned char *buf, int size);

#endif /* __UPD_PARSER_H__ */
