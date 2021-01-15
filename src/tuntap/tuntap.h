#ifndef __TUNTAP_H__
#define __TUNTAP_H__

#include <stdint.h>

/**
 * @brief initialize tuntap interface
 * @param addr proxy ip address
 * @param port proxy port
 * @return 0 on success, -errno on failure
 */
int tuntap_init(char const *addr, uint16_t port);

/**
 * @brief deinitialize tuntap interface
 * @return 0 on success, -errno on failure
 */
int tuntap_deinit();

#endif /* __TUNTAP_H__ */
