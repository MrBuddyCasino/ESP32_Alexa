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
    free(conn->io_ctx);
    url_free(conn->url);
    free(conn);
}


static void asio_registry_poll_connection(asio_registry_t *registry, asio_connection_t *conn)
{
    asio_result_t cb_res;

    // connection was closing last round, now its time to say goodbye
    if(conn->state == ASIO_CONN_CLOSING) {
        conn->state = ASIO_CONN_CLOSED;
    }

    // perform I/O
    conn->io_handler(conn);

    // notify proto
    if(conn->proto_handler) {
        conn->proto_handler(conn);
    }

    // notify user
    if(conn->evt_handler) {
        conn->evt_handler(conn);
    }

    if(conn->user_flags & CONN_FLAG_CLOSE) {
        conn->state = ASIO_CONN_CLOSING;
    }

    // all handlers have been notified thats its game over, remove
    if(conn->state == ASIO_CONN_CLOSED) {
        asio_registry_remove_connection(conn);
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

