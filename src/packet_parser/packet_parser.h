#ifndef __PACKET_PARSER_H__
#define __PACKET_PARSER_H__

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief check if provided ip is ipv4
 * @param ip ip string format
 * @return true if valid, false if not valid
 */
bool is_ip_v4_valid(char const *ip);

/**
 * @brief check if provided ip is ipv6
 * @param ip ip string format
 * @return true if valid, false if not valid
 */
bool is_ip_v6_valid(char const *ip);

/**
 * @brief check if provided packet protocol is udp
 * @param buf packet buf
 * @return true if valid, false if not valid
 */
bool is_packet_udp(uint8_t const *buf);

/**
 * @brief check if provided packet protocol is tcp
 * @param buf packet buf
 * @return true if valid, false if not valid
 */
bool is_packet_tcp(uint8_t const *buf);

/**
 * @brief check if provided packet version is ipv4
 * @param buf packet buf
 * @return true if valid, false if not valid
 */
bool is_packet_ipv4(uint8_t const *buf);

/**
 * @brief check if provided packet version is ipv6
 * @param buf packet buf
 * @return true if valid, false if not valid
 */
bool is_packet_ipv6(uint8_t const *buf);

/**
 * @brief print packet ip header
 * @param buf packet buf
 * @param size buf size
 */
void print_ip_header(uint8_t const *buf, int size);

#endif /* __UPD_PARSER_H__ */
