#include "tuntap.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TUN_DEVICE "/dev/net/tun"

static inline bool _is_device_valid(struct tuntap_device const *dev)
{
    return dev ? true : false;
}

static inline bool _is_fd_valid(struct tuntap_device const *dev)
{
    return dev->fd < 0 ? false : true;
}

int tuntap_open(struct tuntap_device *dev)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("tuntap failed to open tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { .ifr_flags = IFF_NO_PI | dev->flags };
    if (dev->name) {
        strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        printf("tuntap failed to create tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    strncpy(dev->name, ifr.ifr_name, IFNAMSIZ);
    dev->fd = fd;
    dev->flags |= ifr.ifr_flags;

    if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
        printf("tuntap failed to set persistent tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    return 0;
}

int tuntap_close(struct tuntap_device *dev)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap file descriptor invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (ioctl(dev->fd, TUNSETPERSIST, 0) < 0) {
        printf("tuntap failed to disable persistent tuntap! (%d / %s)\r\n",
               errno, strerror(errno));
        return -1;
    }

    if (close(dev->fd) < 0) {
        printf("tuntap failed to close tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    memset(dev, 0, sizeof(*dev));

    return 0;
}

int tuntap_configure(struct tuntap_device *dev, char const *addr,
                     char const *netmask)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    if (!addr || !netmask) {
        errno = -EINVAL;
        printf("tuntap address or netmask invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { 0 };
    struct sockaddr_in sock_addr = { 0 };

    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);

    sock_addr.sin_family = AF_INET;

    if (inet_pton(AF_INET, addr, &sock_addr.sin_addr) <= 0) {
        errno = -EINVAL;
        printf("tuntap address invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    ifr.ifr_addr = *(struct sockaddr *)&sock_addr;

    if (ioctl(dev->socket.fd, SIOCSIFADDR, (caddr_t)&ifr) < 0) {
        printf("tuntap failed to set address! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (inet_pton(AF_INET, netmask, &sock_addr.sin_addr) <= 0) {
        printf("tuntap netmask invalid! (%d / %s)\r\n", errno, strerror(errno));
        errno = -EINVAL;
        return -1;
    }

    ifr.ifr_netmask = *(struct sockaddr *)&sock_addr;

    if (ioctl(dev->socket.fd, SIOCSIFNETMASK, (caddr_t)&ifr) < 0) {
        printf("tuntap failed to set netmask! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    strncpy(dev->addr, addr, sizeof(dev->addr));
    strncpy(dev->netmask, netmask, sizeof(dev->netmask));

    return 0;
}

int tuntap_set_state(struct tuntap_device *dev, bool state)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
    if (fd < 0) {
        printf("tuntap failed to create socket! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { 0 };

    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("tuntap failed to get flags! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (state) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    }
    else {
        ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("tuntap failed to set flags! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    dev->socket.fd = fd;
    dev->socket.flags = ifr.ifr_flags;

    return 0;
}

int tuntap_write(struct tuntap_device const *dev, unsigned char const *buf,
                 size_t len)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap file descriptor invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (write(dev->fd, buf, len) < 0) {
        printf("tuntap failed to write! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    return 0;
}

int tuntap_read(struct tuntap_device const *dev, unsigned char *buf,
                size_t size)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap device invalid! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        printf("tuntap file descriptor invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    int read_bytes = read(dev->fd, buf, size);
    if (read_bytes < 0) {
        printf("tuntap failed to read! (%d / %s)\r\n", errno, strerror(errno));
        return -1;
    }

    return read_bytes;
}

int tuntap_init(struct tuntap_device *dev, char const *addr,
                char const *netmask)
{
    if (tuntap_open(dev) < 0) {
        printf("tuntap open failed! (%d / %s)\r\n", errno, strerror(errno));
        return errno;
    }

    if (tuntap_set_state(dev, true) < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    if (tuntap_configure(dev, addr, netmask) < 0) {
        printf("tuntap configure failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    return 0;
}

int tuntap_deinit(struct tuntap_device *dev)
{
    if (tuntap_set_state(dev, false) < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (tuntap_close(dev) < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }
    return 0;
}
