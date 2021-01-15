#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "log.h"
#include "packet_parser.h"
#include "socks5.h"
#include "tuntap.h"

#define BUFSIZE 65536

struct tuntap_device
{
    char name[IFNAMSIZ + 1];
    char const *addr;
    char const *netmask;
    int fd;
    int flags;
    struct
    {
        char const *ip;
        uint16_t port;
        int fd;
    } proxy;
    struct
    {
        int fd;
        int flags;
    } socket;
};

static struct tuntap_device _device = { .flags = IFF_TUN };

static pthread_t _main_thread_worker;

#define TUN_DEVICE "/dev/net/tun"

static inline bool _is_fd_valid()
{
    return _device.fd < 0 ? false : true;
}

static int tuntap_open()
{
    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) {
        log_error("failed to open tuntap device! (%d / %s)", errno,
                  strerror(errno));
        return -1;
    }

    struct ifreq ifr = { .ifr_flags = IFF_NO_PI | _device.flags };
    if (_device.name) {
        strncpy(ifr.ifr_name, _device.name, IFNAMSIZ);
        ifr.ifr_name[IFNAMSIZ - 1] = 0;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("failed to create tuntap! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    strncpy(_device.name, ifr.ifr_name, IFNAMSIZ);

    _device.fd = fd;
    _device.flags |= ifr.ifr_flags;

    if (ioctl(fd, TUNSETPERSIST, 1) < 0) {
        log_error("failed to set persistent tuntap! (%d / %s)", errno,
                  strerror(errno));
        return -1;
    }

    return 0;
}

static int tuntap_close()
{
    if (!_is_fd_valid()) {
        errno = -EINVAL;
        log_error("file descriptor invalid! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    if (ioctl(_device.fd, TUNSETPERSIST, 0) < 0) {
        log_error("failed to disable persistent tuntap! (%d / %s)", errno,
                  strerror(errno));
        return -1;
    }

    if (close(_device.fd) < 0) {
        log_error("failed to close tuntap device! (%d / %s)", errno,
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
        log_error("address or netmask invalid! (%d / %s)", errno,
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
        log_error("failed to set address! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    sock_addr.sin_addr.s_addr = inet_addr(netmask);
    ifr.ifr_netmask = *(struct sockaddr *)&sock_addr;

    if (ioctl(_device.socket.fd, SIOCSIFNETMASK, (caddr_t)&ifr) < 0) {
        log_error("failed to set netmask! (%d / %s)", errno, strerror(errno));
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
        log_error("failed to set route! (%d / %s)", errno, strerror(errno));
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
        log_error("failed to create socket! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    struct ifreq ifr = { 0 };

    strncpy(ifr.ifr_name, _device.name, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("failed to get flags! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    if (state) {
        ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    }
    else {
        ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("failed to set flags! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    _device.socket.fd = fd;
    _device.socket.flags = ifr.ifr_flags;

    return 0;
}

static int tuntap_connect_to_proxy(char const *ip, uint16_t port)
{
    struct sockaddr_in remote_sock = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr(ip),
        .sin_port = htons(port),
    };

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("tuntap proxy init failed! (%d / %s)", errno,
                  strerror(errno));
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&remote_sock, sizeof(remote_sock)) < 0) {
        log_error("tuntap connect to proxy failed! (%d / %s)", errno,
                  strerror(errno));
        close(fd);
        return -1;
    }

    _device.proxy.fd = fd;
    _device.proxy.ip = ip;
    _device.proxy.port = port;

    return 0;
}

static int read_n(int fd, uint8_t *buf, int n)
{
    int left = n;
    while (left > 0) {
        int nread = 0;
        if ((nread = read(fd, buf, left)) == 0) {
            return 0;
        }
        else {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

static void *_main_thread(void *fd)
{
    int tap_fd = _device.fd;
    int net_fd = _device.proxy.fd;
    int maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;
    uint8_t buffer[BUFSIZE] = { 0 };
    uint16_t nread = 0;
    uint16_t plength = 0;

    while (1) {
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set);
        FD_SET(net_fd, &rd_set);

        int ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (ret < 0) {
            exit(1);
        }

        if (FD_ISSET(tap_fd, &rd_set)) {
            nread = read(tap_fd, buffer, BUFSIZE);
            if (nread == 0) {
                continue;
            }
            if (!is_packet_ipv4(buffer)) {
                continue;
            }
            plength = htons(nread);
            socks5_send_packet(net_fd, _device.proxy.ip, _device.proxy.port,
                               buffer, nread);
        }

        if (FD_ISSET(net_fd, &rd_set)) {
            nread = read_n(net_fd, (uint8_t *)&plength, sizeof(plength));
            if (nread == 0) {
                break;
            }

            print_ip_header(buffer, sizeof(buffer));

            nread = read_n(net_fd, buffer, ntohs(plength));
            write(tap_fd, buffer, nread);
        }
    }

    return NULL;
}

int tuntap_init(char const *addr, uint16_t port)
{
    if (tuntap_open() < 0) {
        log_error("open failed! (%d / %s)", errno, strerror(errno));
        return errno;
    }

    if (tuntap_set_state(true) < 0) {
        log_error("set state failed! (%d / %s)", errno, strerror(errno));
        return errno;
    }

    if (tuntap_configure("10.0.0.1", "255.255.255.0") < 0) {
        log_error("configure failed! (%d / %s)", errno, strerror(errno));
        return errno;
    }

    if (tuntap_connect_to_proxy(addr, port) < 0) {
        log_error("failed to connect to proxy! (%d / %s)", errno,
                  strerror(errno));
        return errno;
    }

    if (pthread_create(&_main_thread_worker, NULL, &_main_thread, &_device.fd)
        != 0) {
        pthread_detach(_main_thread_worker);
        return -1;
    }

    return 0;
}

int tuntap_deinit()
{
    if (tuntap_set_state(false) < 0) {
        log_error("set state failed! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    if (tuntap_close() < 0) {
        log_error("set state failed! (%d / %s)", errno, strerror(errno));
        return -1;
    }

    return 0;
}
