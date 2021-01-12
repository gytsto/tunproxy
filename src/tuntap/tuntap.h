#ifndef __TUNTAP_H__
#define __TUNTAP_H__

/**
 * @brief initialize tuntap interface
 * @param addr ip address
 * @param netmask netmask
 * @return 0 on success, -errno on failure
 */
int tuntap_init(char const *addr, char const *netmask);

/**
 * @brief deinitialize tuntap interface
 * @return 0 on success, -errno on failure
 */
int tuntap_deinit();

#endif /* __TUNTAP_H__ */
