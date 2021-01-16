#ifndef __SOCKS5_H__
#define __SOCKS5_H__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief initialize socks5 proxy socket
 * @param server_ip server ip
 * @param port server port
 * @return 0 on success, -errno on failure
 */
int socks5_init(char const *server_ip, uint16_t port);

/**
 * @brief deinitialize socks5 proxy socket
 * @return 0 on success, -errno on failure
 */
int socks5_deinit();

/**
 * @brief send packet to destination ip via socks5
 * @param fd socks file descriptor
 * @param ip destination ip
 * @param port destination port
 * @param buf pointer to data buffer
 * @param size data buffer size
 * @return 0 on success, -errno on failure
 */
int socks5_send_packet(int fd, const char *ip, uint16_t port, uint8_t *buf,
                       size_t size);

#endif /* __SOCKS5_H__ */
