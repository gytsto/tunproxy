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
        return -1;
    }

    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("Failed to open tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { .ifr_flags = IFF_NO_PI | dev->flags };
    if (dev->name) {
        strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        printf("Failed to create tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    strncpy(dev->name, ifr.ifr_name, IFNAMSIZ);
    dev->fd = fd;
    dev->flags |= ifr.ifr_flags;

    if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
        printf("Failed to set persistent tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    return 0;
}

int tuntap_close(struct tuntap_device *dev)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    if (ioctl(dev->fd, TUNSETPERSIST, 0) < 0) {
        printf("Failed to disable persistent tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (close(dev->fd) < 0) {
        printf("Failed to close tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    memset(dev, 0, sizeof(*dev));

    return 0;
}


int tuntap_set_state(struct tuntap_device *dev, bool state)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
    if (fd < 0) {
        return -1;
    }

    struct ifreq ifr = { 0 };

    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        return -1;
    }

    if (state) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    }
    else {
        ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
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
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    return write(dev->fd, buf, len);
}

int tuntap_read(struct tuntap_device const *dev, unsigned char *buf,
                size_t size)
{
    if (!_is_device_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    if (!_is_fd_valid(dev)) {
        errno = -EINVAL;
        return -1;
    }

    return read(dev->fd, buf, size);
}
