#include <errno.h>
#include <linux/if_tun.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "packet_parser.h"
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
    { SIGHUP , exit_handler },
    { SIGQUIT, exit_handler },
    { SIGKILL, exit_handler },
    // clang-format on
};

int main(int argc, char *argv[])
{
    char *ip = "127.0.0.1";
    uint16_t port = 1080;

    ++argv;
    --argc;

    if (argc > 0) {
        if (strstr(*argv, ":") != NULL) {
            char *end_ptr = NULL;
            ip = strtok_r(*argv, ":", &end_ptr);
            port = atoi(end_ptr);
            ++argv;
            --argc;
        }
        else {
            ip = *argv;
            ++argv;
            --argc;
            if (argc > 0) {
                port = atoi(*argv);
                ++argv;
                --argc;
            }
        }
    }

    if (!is_ip_valid(ip)) {
        errno = -EINVAL;
        fprintf(stderr, "Invalid ip address! (%d / %s)\r\n", errno,
                strerror(errno));
        return -1;
    }

    if (log_init() != 0) {
        fprintf(stderr, "Failed to logging system! (%d / %s)\r\n", errno,
                strerror(errno));
        return -1;
    }

    log_trace("getuid");
    if (getuid() != 0) {
        log_error("Not a root!");
        return errno;
    }

    log_trace("socks5 init");
    if (socks5_init(ip, port) < 0) {
        log_error("Failed to initialize socks5! (%d / %s)", errno,
                  strerror(errno));
        return errno;
    }

    log_trace("tuntap init");
    if (tuntap_init(ip, port) < 0) {
        log_error("Failed to initialize tuntap device! (%d / %s)", errno,
                  strerror(errno));
        return errno;
    }

    log_trace("signal handler init");
    if (signal_handler_init(_signal_table, ARRAY_SIZE(_signal_table)) < 0) {
        log_error("Failed to initialize signal handler! (%d / %s)", errno,
                  strerror(errno));
        return errno;
    }

    while (1)
        ;

    return 0;
}
