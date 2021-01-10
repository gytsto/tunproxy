#ifndef __TUNTAP_H__
#define __TUNTAP_H__

#include <linux/if.h>
#include <netinet/if_ether.h>
#include <stdbool.h>
#include <stdint.h>

struct tuntap_device
{
    char name[IFNAMSIZ + 1];
    char addr[16];
    char netmask[16];
    int fd;
    int flags;
    struct
    {
        int fd;
        int flags;
    } socket;
};

/**
 * @brief open tuntap interface
 * @param dev pointer to tuntap device
 * @return 0 on success, -errno on failure
 */
int tuntap_open(struct tuntap_device *dev);

/**
 * @brief close tuntap interface
 * @param dev pointer to tuntap device
 * @return 0 on success, -errno on failure
 */
int tuntap_close(struct tuntap_device *dev);

/**
 * @brief configure tuntap interface
 * @param dev pointer to tuntap device
 * @param addr ip address
 * @param netmask netmask
 * @return 0 on success, -errno on failure
 */
int tuntap_configure(struct tuntap_device *dev, char const *addr,
                     char const *netmask);

/**
 * @brief set new tuntap socket state
 * @param dev pointer to tuntap device
 * @param state new socket state
 * @return 0 on success, -errno on failure
 */
int tuntap_set_state(struct tuntap_device *dev, bool state);

/**
 * @brief write to tuntap interface
 * @param dev pointer to tuntap device
 * @param buf data buffer
 * @param len data buffer len
 * @return 0 on success, -errno on failure
 */
int tuntap_write(struct tuntap_device const *dev, unsigned char const *buf,
                 size_t len);

/**
 * @brief read from tuntap interface
 * @param dev pointer to tuntap device
 * @param buf data buffer
 * @param len data buffer size
 * @return 0 on success, -errno on failure
 */
int tuntap_read(struct tuntap_device const *dev, unsigned char *buf,
                size_t size);

#endif /* __TUNTAP_H__ */
