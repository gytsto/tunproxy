#include <errno.h>
#include <linux/if_tun.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tuntap.h"

static struct tuntap_device tun_dev = { .flags = IFF_TUN };

int main(int argc, char const *argv[])
{

    if (getuid() != 0) {
        printf("Not a root!\r\n");
        return errno;
    }

    if (tuntap_open(&tun_dev) < 0) {
        printf("%s\r\n", strerror(errno));
        return errno;
    }

    if (tuntap_set_state(&tun_dev, true) < 0) {
        printf("%s\r\n", strerror(errno));
        return errno;
    }

    while (1) {
        unsigned char buf[1024] = { 0 };
        int read_bytes = tuntap_read(&tun_dev, buf, sizeof(buf));
        if (read_bytes > 0) {
            printf("Read bytes: %d, buffer:\r\n", read_bytes);
            for (int i = 0; i < sizeof(buf); i++) {
                printf("%x ", buf[i]);
            }
            printf("\r\n");
        }
    }

    // if (tuntap_close(&tun_dev) < 0) {
    //     printf("%s\r\n", strerror(errno));
    //     return errno;
    // }

    return 0;
}
