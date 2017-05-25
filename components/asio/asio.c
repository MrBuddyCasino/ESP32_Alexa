/*
 * event_loop.c
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/unistd.h>
#include <sys/time.h>
#include <lwip/sockets.h>

#include "esp_log.h"
#include "common_buffer.h"
#include "url_parser.h"
#include "asio.h"
#include "asio_socket.h"


#define TAG "asio"


void asio_registry_init(asio_registry_t **registry, void *user_data)
{
    *registry = calloc(1, sizeof(asio_registry_t));
    (*registry)->user_data = user_data;
    (*registry)->max_connections = 16;
}

void asio_registry_destroy(asio_registry_t *registry)
{
    for (int i = 0; i < registry->max_connections; i++) {
        if (registry->connections[i] != NULL) {
            asio_registry_remove_connection(registry->connections[i]);
            registry->connections[i] = NULL;
        }
    }

    free(registry);
}

int asio_registry_add_connection(asio_registry_t *registry, asio_connection_t *conn)
{
    ESP_LOGI(TAG, "adding connection: %s", conn->url->authority);

    for (int i = 0; i < registry->max_connections; i++) {
        if (registry->connections[i] == NULL) {
            registry->connections[i] = conn;
            return 0;
        }
    }

    return -1;
}

void asio_registry_remove_connection(asio_connection_t *conn)
{
    if(conn == NULL) return;

    ESP_LOGI(TAG, "removing connection: %s", conn->url->authority);

    asio_registry_t *registry = conn->registry;
    for (int i = 0; i < registry->max_connections; i++) {
        if (registry->connections[i] == conn) {
            registry->connections[i] = NULL;
            break;
        }
    }

    free(conn->proto_context);
    url_free(conn->url);
    close(conn->fd);
    buf_destroy(conn->recv_buf);
    buf_destroy(conn->send_buf);
    free(conn);
}

static asio_poll_res_t do_poll(asio_connection_t *conn, int *flags)
{
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

    /* send */

    size_t bytes_unsent = buf_data_unread(conn->send_buf);
    if(FD_ISSET(conn->fd, &writeset) && bytes_unsent > 0)
    {
        int bytes_sent = send(conn->fd, conn->send_buf->read_pos, bytes_unsent, 0);
        if (bytes_sent <= 0) {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                // OK
            } else
            {
                ESP_LOGE(TAG, "socket closed");
                return ASIO_POLL_ERR_CLOSED;
            }
        } else
        {
            *flags |= POLL_FLAG_SENT;
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

    if(FD_ISSET(conn->fd, &readset) && free_cap > 0)
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
                return ASIO_POLL_ERR_CLOSED;
            }
        } else
        {
            buf_fill(conn->recv_buf, bytes_recv);
            *flags |= POLL_FLAG_RECV;
        }
    }

    /* error */

    if(FD_ISSET(conn->fd, &errset))
    {
        // TODO
        ESP_LOGE(TAG, "fd error");
        return ASIO_POLL_ERR_CLOSED;
    }

    return ASIO_POLL_OK;
}

static void asio_registry_poll_connection(asio_registry_t *registry, asio_connection_t *conn)
{
    asio_cb_res_t cb_res;

    switch (conn->state)
    {
        case ASIO_CONN_NEW:
            conn->state = ASIO_CONN_CONNECTING;
            int fd = asio_socket_connect(conn->url->host, conn->url->port, true);

            // connect failed, next poll will clean it up
            if(fd < 0) {
                conn->state = ASIO_CONN_CLOSED;
                break;
            }

            conn->fd = fd;
            conn->state = ASIO_CONN_CONNECTED;

            // notify proto
            if(conn->proto_handler) {
                conn->proto_handler(conn, ASIO_EVT_CONNECTED, registry->user_data);
            }

            // notify user
            conn->evt_handler(conn, ASIO_EVT_CONNECTED, registry->user_data);

            break;

        case ASIO_CONN_CONNECTING:
            break;

        case ASIO_CONN_CONNECTED:
            ;
            int flags = 0;
            asio_poll_res_t poll_res = do_poll(conn, &flags);
            switch(poll_res) {
                case ASIO_POLL_OK:

                    if(flags & POLL_FLAG_RECV)
                    {
                        cb_res = conn->proto_handler(conn, ASIO_EVT_DATA_RECV, registry->user_data);

                        if(cb_res == ASIO_CB_CLOSE_CONNECTION || (conn->flags & CONN_FLAG_CLOSE)) {
                            close(conn->fd);
                            conn->state = ASIO_CONN_CLOSED;
                        }

                        conn->evt_handler(conn, ASIO_EVT_DATA_RECV, registry->user_data);
                    }

                    if(flags & POLL_FLAG_SENT) {
                        ;
                    }

                break;

                case ASIO_POLL_ERR:
                break;

                case ASIO_POLL_ERR_CLOSED:
                    close(conn->fd);
                    conn->state = ASIO_CONN_CLOSED;
                break;
            }

            break;

        case ASIO_CONN_CLOSED:
            // notify proto handler
            if(conn->proto_handler) {
                conn->proto_handler(conn, ASIO_EVT_CLOSE, registry->user_data);
            }

            // notify user
            conn->evt_handler(conn, ASIO_EVT_CLOSE, registry->user_data);

            // cleanup
            asio_registry_remove_connection(conn);
            break;
    }
}

int asio_registry_poll(asio_registry_t *registry)
{
    uint8_t num_conn = 0;
    for (int i = 0; i < registry->max_connections; i++) {
        asio_connection_t *conn = registry->connections[i];
        if (conn == NULL) continue;

        asio_registry_poll_connection(registry, conn);
        num_conn++;
    }

    return num_conn;
}

