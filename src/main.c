#include <errno.h>
#include <linux/if_tun.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "signal_handler.h"
#include "tuntap.h"
#include "util.h"

static struct tuntap_device tun_dev = { .flags = IFF_TUN };
static volatile int running = 1;

static void exit_handler(int data)
{
    tuntap_deinit(&tun_dev);
    running = 0;
    printf("\r\n");
    exit(errno);
}

static const struct signal_handler _signal_table[] = {
    // clang-format off
    { SIGINT , exit_handler },
    { SIGTERM, exit_handler },
    { SIGABRT, exit_handler },
    // clang-format on
};

int main(int argc, char const *argv[])
{
    if (getuid() != 0) {
        printf("Not a root!\r\n");
        return errno;
    }

    if (signal_handler_init(_signal_table, ARRAY_SIZE(_signal_table)) < 0) {
        printf("Failed to initialize signal handler! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    if (tuntap_init(&tun_dev, "10.0.0.1", "255.255.255.0") < 0) {
        printf("Failed to initialize tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    while (running) {
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

    return 0;
}
