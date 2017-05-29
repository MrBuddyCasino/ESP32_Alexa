/*
 * asio_socket.c
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include "esp_log.h"
#include "url_parser.h"
#include "common_buffer.h"
#include "asio.h"

#define TAG "asio_handler_socket"
#define SOCKET             int
#define INVALID_SOCKET     (-1)


int asio_socket_connect(const char *host, uint16_t n_port, bool verbose)
{
    struct addrinfo hints, *si, *p;
    SOCKET fd;
    int err;

    /* port to string */
    const char port[6];
    itoa(n_port, (char*) &port, 10);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &si);
    if (err != 0) {
        fprintf(stderr, "ERROR: getaddrinfo(): %d\n", err);
        return INVALID_SOCKET;
    }
    fd = INVALID_SOCKET;
    for (p = si; p != NULL; p = p->ai_next) {
        if (verbose) {
            struct sockaddr *sa;
            void *addr;
            char tmp[INET6_ADDRSTRLEN + 50];

            sa = (struct sockaddr *)p->ai_addr;
            if (sa->sa_family == AF_INET) {
                addr = &((struct sockaddr_in *)sa)->sin_addr;
            } else if (sa->sa_family == AF_INET6) {
                addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
            } else {
                addr = NULL;
            }
            if (addr != NULL) {
                if (!inet_ntop(p->ai_family, addr,
                    tmp, sizeof tmp))
                {
                    strcpy(tmp, "<invalid>");
                }
            } else {
                sprintf(tmp, "<unknown family: %d>",
                    (int)sa->sa_family);
            }
            fprintf(stderr, "connecting to: %s\n", tmp);
        }
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCKET) {
            if (verbose) {
                perror("socket()");
            }
            continue;
        }

        if (p->ai_protocol == IPPROTO_TCP) {
            int opt = 1;
            if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int))) {
                perror("setsockopt(TCP_NDELAY) failed");
                continue;
            }
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) == INVALID_SOCKET) {
            if (verbose) {
                perror("connect()");
            }

            close(fd);

            continue;
        }
        break;
    }
    if (p == NULL) {
        freeaddrinfo(si);
        fprintf(stderr, "ERROR: failed to connect\n");
        return INVALID_SOCKET;
    }
    freeaddrinfo(si);
    if (verbose) {
        fprintf(stderr, "connected.\n");
    }

    /*
     * We make the socket non-blocking, since we are going to use
     * poll() or select() to organise I/O.
     */
    fcntl(fd, F_SETFL, O_NONBLOCK);

    return fd;
}

/* perform direct I/O to/from socket to buffers */
asio_cb_res_t asio_socket_ready(asio_connection_t *conn)
{
    /* send */

    size_t bytes_unsent = buf_data_unread(conn->send_buf);
    if((conn->poll_flags & POLL_FLAG_SEND) && bytes_unsent > 0)
    {
        int bytes_sent = send(conn->fd, conn->send_buf->read_pos, bytes_unsent, 0);
        if (bytes_sent <= 0) {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                // OK
            } else
            {
                ESP_LOGE(TAG, "socket closed");
                return ASIO_CB_CLOSE_CONNECTION;
            }
        } else
        {
            buf_drain(conn->send_buf, bytes_sent);
        }
    }

    /* receive */

    size_t free_cap = buf_free_capacity(conn->recv_buf);
    // need to purge stale bytes
    if(free_cap < 1 && buf_free_capacity_after_purge(conn->recv_buf) > 0) {
        buf_move_remaining_bytes_to_front(conn->recv_buf);
        free_cap = buf_free_capacity(conn->recv_buf);
    }

    if((conn->poll_flags & POLL_FLAG_RECV) && free_cap > 0)
    {
        int bytes_recv = recv(conn->fd, conn->recv_buf->write_pos, free_cap, 0);

        if (bytes_recv <= 0)
        {
            if (errno == EINTR || errno == EWOULDBLOCK)
            {
                // OK
            } else
            {
                ESP_LOGE(TAG, "socket closed");
                return ASIO_CB_CLOSE_CONNECTION;
            }
        } else
        {
            buf_fill(conn->recv_buf, bytes_recv);
        }
    }

    /* error */

    if(conn->poll_flags & POLL_FLAG_ERR)
    {
        // TODO
        ESP_LOGE(TAG, "POLL_FLAG_ERR set");
        return ASIO_CB_CLOSE_CONNECTION;
    }

    return ASIO_CB_OK;
}


asio_poll_res_t asio_socket_poll(asio_connection_t *conn)
{
    // reset flags
    conn->poll_flags = 0;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    fd_set readset;
    fd_set writeset;
    fd_set errset;

    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&errset);

    FD_SET(conn->fd, &readset);
    FD_SET(conn->fd, &writeset);
    FD_SET(conn->fd, &errset);

    int n = select(conn->fd + 1, &readset, &writeset, &errset, &tv);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }
        perror("ERROR: select()");
        return ASIO_POLL_ERR;
    }

    // nothing interesting happened
    if (n == 0) {
        return ASIO_POLL_OK;
    }

    if(FD_ISSET(conn->fd, &writeset))
        conn->poll_flags |=  POLL_FLAG_SEND;

    if(FD_ISSET(conn->fd, &readset))
        conn->poll_flags |=  POLL_FLAG_RECV;

    if(FD_ISSET(conn->fd, &errset))
        conn->poll_flags |=  POLL_FLAG_ERR;

    return ASIO_POLL_OK;
}

void asio_socket_free(asio_connection_t *conn)
{
    close(conn->fd);
    buf_destroy(conn->recv_buf);
    buf_destroy(conn->send_buf);
}


asio_cb_res_t asio_socket_event(asio_connection_t *conn, asio_event_t event)
{
    switch (event) {
        case ASIO_EVT_NEW:
            ;
            int fd = asio_socket_connect(conn->url->host, conn->url->port, true);
            if(fd < 0) {
                conn->state = ASIO_CONN_CLOSED;
                return ASIO_CB_ERR;
            }
            conn->fd = fd;
            conn->state = ASIO_CONN_CONNECTED;
            conn->poll_handler = asio_socket_poll;
            break;

        case ASIO_EVT_CONNECTED:
            break;

        case ASIO_EVT_CLOSE:
            asio_socket_free(conn);
            break;

        case ASIO_EVT_SOCKET_READY:
            return asio_socket_ready(conn);
            break;
    }

    return ASIO_CB_OK;
}


asio_connection_t *asio_new_socket_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, void *user_data)
{
    url_t *url = url_parse(uri);
    if(!url)
        return NULL;

    asio_connection_t *conn = calloc(1, sizeof(asio_connection_t));
    if(conn == NULL) {
        ESP_LOGE(TAG, "calloc() failed: asio_connection_t");
        return NULL;
    }

    conn->registry = registry;
    conn->url = url;
    conn->user_data = user_data;
    conn->transport = transport_proto;
    conn->fd = -1;
    conn->io_handler = asio_socket_event;
    conn->state = ASIO_CONN_NEW;

    /* ssl has its own buffers */
    if(transport_proto != ASIO_TCP_SSL) {
        conn->send_buf = buf_create(1024);
        conn->recv_buf = buf_create(1024);
    }

    if(asio_registry_add_connection(registry, conn) < 0) {
        ESP_LOGE(TAG, "failed to add connection");
        asio_registry_remove_connection(conn);
        return NULL;
    }

    return conn;
}
