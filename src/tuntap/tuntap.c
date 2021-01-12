#include "tuntap.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
struct tuntap_device
{
    char name[IFNAMSIZ + 1];
    char const *addr;
    char const *netmask;
    int fd;
    int flags;
    struct
    {
        int fd;
        int flags;
    } socket;
};

static struct tuntap_device _device = { .flags = IFF_TUN };

#define TUN_DEVICE "/dev/net/tun"

static inline bool _is_fd_valid()
{
    return _device.fd < 0 ? false : true;
}

static int tuntap_open()
{
    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        printf("tuntap failed to open tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { .ifr_flags = IFF_NO_PI | _device.flags };
    if (_device.name) {
        strncpy(ifr.ifr_name, _device.name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        printf("tuntap failed to create tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    strncpy(_device.name, ifr.ifr_name, IFNAMSIZ);

    _device.fd = fd;
    _device.flags |= ifr.ifr_flags;

    if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
        printf("tuntap failed to set persistent tuntap! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    return 0;
}

static int tuntap_close()
{
    if (!_is_fd_valid()) {
        errno = -EINVAL;
        printf("tuntap file descriptor invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (ioctl(_device.fd, TUNSETPERSIST, 0) < 0) {
        printf("tuntap failed to disable persistent tuntap! (%d / %s)\r\n",
               errno, strerror(errno));
        return -1;
    }

    if (close(_device.fd) < 0) {
        printf("tuntap failed to close tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    _device.fd = -1;

    return 0;
}

static int tuntap_configure(char const *addr, char const *netmask)
{
    if (!addr || !netmask) {
        errno = -EINVAL;
        printf("tuntap address or netmask invalid! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { 0 };
    struct sockaddr_in sock_addr = { 0 };

    strncpy(ifr.ifr_name, _device.name, IFNAMSIZ);

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = inet_addr(addr);
    ifr.ifr_addr = *(struct sockaddr *)&sock_addr;

    if (ioctl(_device.socket.fd, SIOCSIFADDR, (caddr_t)&ifr) < 0) {
        printf("tuntap failed to set address! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    sock_addr.sin_addr.s_addr = inet_addr(netmask);
    ifr.ifr_netmask = *(struct sockaddr *)&sock_addr;

    if (ioctl(_device.socket.fd, SIOCSIFNETMASK, (caddr_t)&ifr) < 0) {
        printf("tuntap failed to set netmask! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct rtentry route = { 0 };
    struct sockaddr_in *route_addr = (struct sockaddr_in *)&route.rt_gateway;

    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = inet_addr(addr);

    route_addr = (struct sockaddr_in *)&route.rt_dst;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = INADDR_ANY;

    route_addr = (struct sockaddr_in *)&route.rt_genmask;
    route_addr->sin_family = AF_INET;
    route_addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;
    route.rt_dev = _device.name;

    if (ioctl(_device.socket.fd, SIOCADDRT, &route) < 0) {
        printf("tuntap failed to set route! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    _device.addr = addr;
    _device.netmask = netmask;

    return 0;
}

static int tuntap_set_state(bool state)
{
    int fd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
    if (fd < 0) {
        printf("tuntap failed to create socket! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    struct ifreq ifr = { 0 };

    strncpy(ifr.ifr_name, _device.name, IFNAMSIZ);
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

    _device.socket.fd = fd;
    _device.socket.flags = ifr.ifr_flags;

    return 0;
}

int tuntap_init(char const *addr, char const *netmask)
{
    if (tuntap_open() < 0) {
        printf("tuntap open failed! (%d / %s)\r\n", errno, strerror(errno));
        return errno;
    }

    if (tuntap_set_state(true) < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    if (tuntap_configure(addr, netmask) < 0) {
        printf("tuntap configure failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    return 0;
}

int tuntap_deinit()
{
    if (tuntap_set_state(false) < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    if (tuntap_close() < 0) {
        printf("tuntap set state failed! (%d / %s)\r\n", errno,
               strerror(errno));
        return -1;
    }

    return 0;
}
