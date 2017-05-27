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
#include "brssl.h"
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

    free(conn->proto_ctx);
    url_free(conn->url);
    close(conn->fd);
    buf_destroy(conn->recv_buf);
    buf_destroy(conn->send_buf);
    free(conn);
}


static void asio_registry_poll_connection(asio_registry_t *registry, asio_connection_t *conn)
{
    asio_cb_res_t cb_res;

    switch (conn->state)
    {
        case ASIO_CONN_NEW:
            conn->io_handler(conn, ASIO_EVT_NEW, registry->user_data);

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
            asio_poll_res_t poll_res = conn->poll_handler(conn);
            switch(poll_res)
            {
                case ASIO_POLL_OK:
                    if(conn->poll_flags > 0)
                    {
                        // perform I/O
                        if(conn->io_handler(conn, ASIO_EVT_SOCKET_READY, registry->user_data) != ASIO_CB_OK) {
                            // TODO
                            ESP_LOGE(TAG, "io_cb() failed");
                        }

                        cb_res = conn->proto_handler(conn, ASIO_EVT_SOCKET_READY, registry->user_data);

                        if(cb_res == ASIO_CB_CLOSE_CONNECTION || (conn->user_flags & CONN_FLAG_CLOSE)) {
                            conn->state = ASIO_CONN_CLOSED;
                        }

                        // unnecessary?
                        // conn->evt_handler(conn, ASIO_EVT_SOCKET_READY, registry->user_data);
                    }
                break;

                case ASIO_POLL_ERR:
                    ESP_LOGE(TAG, "got ASIO_POLL_ERR");
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

