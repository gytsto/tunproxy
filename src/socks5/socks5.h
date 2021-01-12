#ifndef __SOCKS5_H__
#define __SOCKS5_H__

#include <stdint.h>

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

#endif /* __SOCKS5_H__ */
