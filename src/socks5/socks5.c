#include "socks5.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include "log.h"
#include "packet_parser.h"

#define BUFSIZE     65536
#define MAX_CLIENTS 25

enum version
{
    RESERVED = 0x00,
    VERSION4 = 0x04,
    VERSION5 = 0x05
};

enum authentication_method
{
    NOAUTH = 0x00,
    USERPASS = 0x02,
    NOMETHOD = 0xff
};

enum socks_auth_userpass
{
    AUTH_OK = 0x00,
    AUTH_VERSION = 0x01,
    AUTH_FAIL = 0xff
};

enum command
{
    CONNECT = 0x01,
    BIND = 0x02,
    UDPASSOCIATE = 0x03
};

enum type
{
    IPV4 = 0x01,
    DOMAIN = 0x03,
};

enum status
{
    SUCCESS = 0x0,
    SERVER_FAIL = 0x01,
    NOT_ALLOWED = 0x02,
    NET_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONN_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    CMD_NOT_SUPPORTED = 0x07,
    ADDR_TYPE_NOT_SUP = 0x08,
};

struct socks5_device
{
    int fd;
    const char *ip;
    uint16_t port;
    enum version ver;
    enum authentication_method method;
    const char *username;
    const char *password;
};

static pthread_t _main_thread_worker;

static struct socks5_device _device = {
    .fd = -1,
    .ip = "127.0.0.1",
    .port = 1080,
    .ver = VERSION5,
    .method = NOAUTH,
    .username = NULL,
    .password = NULL,
};

static volatile bool stop_main_thread = false;
static volatile bool stop_client_thread = false;

static int socks5_connect(enum type type, char const *addr, uint16_t port)
{
    int fd = -1;
    struct sockaddr_in remote_sock = { 0 };

    switch (type) {
        case IPV4: {
            remote_sock.sin_family = AF_INET;
            remote_sock.sin_addr.s_addr = inet_addr(addr);
            remote_sock.sin_port = htons(port);

            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                log_error("socks5 init sock failed! (%d / %s)", errno,
                          strerror(errno));
                return -1;
            }

            if (connect(fd, (struct sockaddr *)&remote_sock,
                        sizeof(remote_sock))
                < 0) {
                log_error("socks5 connect sock failed! (%d / %s)", errno,
                          strerror(errno));
                close(fd);
                return -1;
            }

            break;
        }
        case DOMAIN: {
            struct addrinfo *remote_addr = NULL;
            char port_number[6] = { 0 };
            snprintf(port_number, sizeof(port_number), "%d", port);
            int err = getaddrinfo(addr, port_number, NULL, &remote_addr);
            if (err < 0) {
                log_error("socks5 get addr info failed! (%d / %s)", errno,
                          strerror(errno));
                return -1;
            }
            else if (err == 0) {
                struct addrinfo *r;
                for (r = remote_addr; r != NULL; r = r->ai_next) {
                    fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
                    if (fd == -1) {
                        log_error("socks5 domain socket init failed! (%d / %s)",
                                  errno, strerror(errno));
                        continue;
                    }
                    err = connect(fd, r->ai_addr, r->ai_addrlen);
                    if (err == 0) {
                        log_error("socks5 connected to remote! (%d / %s)",
                                  errno, strerror(errno));
                        freeaddrinfo(remote_addr);
                        return fd;
                    }
                    else {
                        log_error(
                            "socks5 failed to connect to remote! (%d / %s)",
                            errno, strerror(errno));
                        close(fd);
                    }
                }
            }
            freeaddrinfo(remote_addr);
            return -1;
        }
        default: {
            log_error("socks5 type (%d) not supported! (%d / %s)", type, errno,
                      strerror(errno));
            errno = -EINVAL;
            return -1;
        }
    }

    return fd;
}

static int socks5_get_version(int fd)
{
    uint8_t init_buf[2] = { 0 };
    int bytes = read(fd, init_buf, sizeof(init_buf));
    if (bytes != 2) {
        log_error("socks5 failed to get initial packet with version (%d / %s)",
                  errno, strerror(errno));
        return -1;
    }

    log_info("Version: %x, method: %x", init_buf[0], init_buf[1]);

    if (init_buf[0] != _device.ver) {
        return -1;
    }

    return init_buf[1];
}

static int socks5_authentication(int fd, int method_count)
{
    bool is_supported = false;
    for (int i = 0; i < method_count; i++) {
        uint8_t method = 0;
        read(fd, &method, sizeof(method));
        if (method == _device.method) {
            log_info("method supported: %u", method);
            is_supported = true;
            break;
        }
    }

    if (!is_supported) {
        uint8_t response[2] = { VERSION5, NOMETHOD };
        write(fd, response, sizeof(response));
        return -1;
    }

    switch (_device.method) {
        case NOAUTH: {
            uint8_t response[2] = { VERSION5, NOAUTH };
            write(fd, response, sizeof(response));
            return 0;
        }
        case USERPASS: {
            uint8_t response[2] = { VERSION5, USERPASS };
            write(fd, response, sizeof(response));

            uint8_t msg;
            read(fd, &msg, sizeof(msg));

            uint8_t username_size = 0;
            read(fd, &username_size, sizeof(username_size));

            char username[username_size];
            memset(username, 0, sizeof(username));

            read(fd, &username, username_size);
            username[username_size] = 0;

            uint8_t user_password_size = 0;
            read(fd, &user_password_size, sizeof(user_password_size));

            char user_password[user_password_size];
            memset(user_password, 0, sizeof(user_password));

            read(fd, &user_password, user_password_size);
            user_password[user_password_size] = 0;

            bool _is_valid = (!strcmp(username, _device.username)
                              && !strcmp(user_password, _device.password));

            response[0] = AUTH_VERSION;
            response[1] = _is_valid ? AUTH_OK : AUTH_FAIL;
            write(fd, response, sizeof(response));

            return 0;
        }
        case NOMETHOD:
        default: {
            return -1;
        }
    }

    return 0;
}

static int socks5_get_command(int fd, enum type *type)
{
    uint8_t data[4] = { 0 };
    int bytes = read(fd, data, sizeof(data));
    *type = data[3];
    return bytes < 0 && bytes != sizeof(data) ? -1 : 0;
}

static uint16_t socks5_get_port(int fd)
{
    uint16_t port = 0;
    read(fd, (uint8_t *)&port, sizeof(port));
    return port;
}

static void _dump(uint8_t *buf, size_t size)
{
    for (int i = 0; i < size; i++) {
        printf("%u ", buf[i]);
    }
    printf("\r\n");
}

static char *socks5_get_ip(int fd)
{
    uint8_t buf[4] = { 0 };
    read(fd, buf, sizeof(buf));
    _dump(buf, sizeof(buf));
    char *ip = calloc(16, 1);
    inet_ntop(AF_INET, buf, ip, 16);
    ip[16] = 0;
    return ip;
}

static char *socks5_get_domain(int fd, uint8_t *size)
{
    uint8_t domain_size = 0;

    read(fd, &domain_size, sizeof(domain_size));

    char *domain = calloc(domain_size, sizeof(char));

    read(fd, domain, domain_size);

    domain[domain_size] = 0;
    *size = domain_size;

    return domain;
}

static int socks5_send_response(int fd, char *ip, size_t size, uint16_t port,
                                enum type type)
{
    uint8_t response[] = { VERSION5, SUCCESS, RESERVED, type };
    write(fd, response, sizeof(response));
    write(fd, ip, size);
    write(fd, &port, sizeof(port));
    return 0;
}

static void socks5_pipe(int fd0, int fd1)
{
    int maxfd = (fd0 > fd1) ? fd0 : fd1;
    fd_set rd_set = { 0 };
    size_t nread = 0;
    uint8_t buffer_r[BUFSIZE] = { 0 };

    while (1) {
        FD_ZERO(&rd_set);
        FD_SET(fd0, &rd_set);
        FD_SET(fd1, &rd_set);
        int ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (FD_ISSET(fd0, &rd_set)) {
            nread = recv(fd0, buffer_r, BUFSIZE, 0);
            if (!nread) {
                break;
            }
            send(fd1, (const void *)buffer_r, nread, 0);
        }

        if (FD_ISSET(fd1, &rd_set)) {
            nread = recv(fd1, buffer_r, BUFSIZE, 0);
            if (!nread) {
                break;
            }
            send(fd0, (const void *)buffer_r, nread, 0);
        }
    }
}

static void *_client_thread(void *fd)
{
    while (!stop_client_thread) {
        int net_fd = *(int *)fd;
        int inet_fd = -1;
        enum type type = 0;
        char *remote_addr = NULL;
        uint8_t remote_addr_size = 4;
        uint16_t port = 0;

        int method_count = socks5_get_version(net_fd);
        if (method_count < 0) {
            log_error("Failed to verify version!");
            exit(-1);
            // return NULL;
        }

        if (socks5_authentication(net_fd, method_count) < 0) {
            log_error("Failed authentification!");
            exit(-1);
            // return NULL;
        }
        log_info("Authentification success!");

        if (socks5_get_command(net_fd, &type) < 0) {
            log_error("Failed to get command!");
            exit(-1);
            // return NULL;
        }
        log_info("Command type %d success!", type);

        switch (type) {
            case IPV4: {
                remote_addr = socks5_get_ip(net_fd);
                port = socks5_get_port(net_fd);
                log_info("remote ip address: %s : %u", remote_addr, port);
                inet_fd = socks5_connect(IPV4, remote_addr, ntohs(port));
                if (inet_fd < 0) {
                    log_error("failed to connect to socket");
                    // return NULL;
                }

                break;
            }
            case DOMAIN: {
                remote_addr = socks5_get_domain(net_fd, &remote_addr_size);
                port = socks5_get_port(net_fd);
                log_info("remote domain address: %s : %u", remote_addr, port);
                inet_fd = socks5_connect(DOMAIN, remote_addr, ntohs(port));
                if (inet_fd < 0) {
                    log_error("failed to connect to socket");
                    // return NULL;
                }
                break;
            }
            default: {
                log_error("Not supported type %u!", type);
                errno = -EINVAL;
                // return NULL;
            }
        }

        if (socks5_send_response(net_fd, remote_addr, remote_addr_size, port,
                                 type)
            < 0) {
            log_error("Failed to send response");
            // return NULL;
        }

        if (remote_addr) {
            free(remote_addr);
        }

        socks5_pipe(inet_fd, net_fd);

        close(inet_fd);
        close(net_fd);
    }

    return NULL;
}

static void *_main_thread(void *fd)
{
    int sock_fd = *(int *)fd;
    while (!stop_main_thread) {
        struct sockaddr_in remote = { 0 };
        socklen_t remotelen = 0;
        pthread_t worker = 0;

        log_info("waiting for socks5 connections!");
        int net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen);
        if (net_fd < 0) {
            log_error("socks5 failed to accept client (%u / %s)", errno,
                      strerror(errno));
        }

        int one = 1;
        if (setsockopt(sock_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
            log_error("socks5 client socket option failed (%u / %s)", errno,
                      strerror(errno));
        }

        log_info("accepted connection");
        if (pthread_create(&worker, NULL, &_client_thread, &net_fd) != 0) {
            pthread_detach(worker);
        }
    }
    return NULL;
}

int socks5_init(char const *server_ip, uint16_t port)
{
    int optval = 1;

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        log_error("socks5 socket init failed (%u / %s)", errno,
                  strerror(errno));
        return -1;
    }

    // int flags = fcntl(sock_fd, F_GETFL);
    // fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
        < 0) {
        log_error("socks5 socket option failed (%u / %s)", errno,
                  strerror(errno));
        return -1;
    }

    struct sockaddr_in local = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(server_ip),
    };

    if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        log_error("socks5 socket bind failed (%u / %s)", errno,
                  strerror(errno));
        return -1;
    }

    if (listen(sock_fd, MAX_CLIENTS) < 0) {
        log_error("socks5 socket listen start failed (%u / %s)", errno,
                  strerror(errno));
        return -1;
    }

    _device.fd = sock_fd;
    _device.ip = server_ip;
    _device.port = port;

    log_info("Start listening on %s:%u", _device.ip, _device.port);

    if (pthread_create(&_main_thread_worker, NULL, &_main_thread, &_device.fd)
        != 0) {
        pthread_detach(_main_thread_worker);
        return -1;
    }

    return 0;
}

int socks5_deinit()
{
    close(_device.fd);
    stop_main_thread = true;
    stop_client_thread = true;
    return 0;
}

/* client side */
int socks5_send_connect_request(int fd, const char *ip, uint8_t len,
                                uint16_t port)
{
    enum type type = DOMAIN;
    if (is_ip_v4_valid(ip)) {
        type = IPV4;
    }
    else if (is_ip_v6_valid(ip)) {
        log_error("not supported ip");
        return -1;
    }

    switch (type) {
        case IPV4: {
            uint8_t buf[1024] = { VERSION5, UDPASSOCIATE, RESERVED, IPV4 };
            size_t buf_len = 4;
            uint8_t req_ip[4] = { 0 };
            inet_pton(AF_INET, ip, req_ip);
            memcpy(buf + buf_len, req_ip, sizeof(req_ip));
            buf_len += sizeof(req_ip);
            memcpy(buf + buf_len, &port, sizeof(port));
            buf_len += sizeof(port);
            buf[buf_len] = 0;
            return write(fd, buf, buf_len);
        }
        case DOMAIN: {
            uint8_t buf[1024] = { VERSION5, UDPASSOCIATE, RESERVED, DOMAIN };
            size_t buf_len = 4;
            memcpy(buf + buf_len, &len, sizeof(len));
            buf_len += sizeof(len);
            memcpy(buf + buf_len, ip, len);
            buf_len += len;
            memcpy(buf + buf_len, &port, sizeof(port));
            buf_len += sizeof(port);
            buf[buf_len] = 0;
            return write(fd, buf, buf_len);
        }
        default:
            return -1;
    }
    return -1;
}

int socks5_send_method(int fd)
{
    char buf[3] = { VERSION5, 0x01, NOAUTH };
    return write(fd, buf, sizeof(buf));
}

int socks5_recv_method(int fd)
{
    uint8_t method_buf[2] = { 0 };

    read(fd, method_buf, 2);

    if (method_buf[0] != VERSION5) {
        log_error("socks5 version failure");
        return -1;
    }

    if (method_buf[1] != NOAUTH) {
        log_error("socks5 authentication method mismatch");
        return -1;
    }

    return 0;
}

int socks5_send_packet(int fd, const char *ip, uint16_t port, uint8_t *buf,
                       size_t size)
{
    struct sockaddr_in dst = { .sin_addr.s_addr =
                                   ((struct iphdr *)buf)->daddr };
    char *dest = inet_ntoa(dst.sin_addr);

    socks5_send_method(fd);
    socks5_recv_method(fd);
    socks5_send_connect_request(fd, dest, strlen(dest), port);

    return write(fd, buf, size);
}
