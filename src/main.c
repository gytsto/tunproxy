#include <errno.h>
#include <linux/if_tun.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "signal_handler.h"
#include "socks5.h"
#include "tuntap.h"
#include "udp_parser.h"
#include "util.h"

static void exit_handler(int data)
{
    tuntap_deinit();
    socks5_deinit();
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
    printf("getuid\r\n");
    if (getuid() != 0) {
        printf("Not a root!\r\n");
        return errno;
    }

    printf("socks5 init\r\n");
    if (socks5_init("127.0.0.1", 1080) < 0) {
        printf("Failed to initialize socks5! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    printf("tuntap init\r\n");
    if (tuntap_init("10.0.0.1", "255.255.255.0") < 0) {
        printf("Failed to initialize tuntap device! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    printf("signal handler init\r\n");
    if (signal_handler_init(_signal_table, ARRAY_SIZE(_signal_table)) < 0) {
        printf("Failed to initialize signal handler! (%d / %s)\r\n", errno,
               strerror(errno));
        return errno;
    }

    while(1);

    return 0;
}
