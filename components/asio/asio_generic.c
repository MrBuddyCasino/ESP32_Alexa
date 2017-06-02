/*
 * asio_generic.c
 *
 *  Created on: 30.05.2017
 *      Author: michaelboeckling
 */

#include "stdlib.h"
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_log.h"

#include "url_parser.h"
#include "asio.h"
#include "asio_generic.h"

#define TAG "asio_gpio"


typedef struct {
    asio_generic_callback_t callback;
    void *cb_arg;
    void *user_data;
} asio_generic_ctx_t;


void asio_generic_destroy(asio_connection_t *conn)
{
    free(conn->io_ctx);
}

asio_result_t asio_generic_handler(asio_connection_t *conn)
{
    asio_generic_ctx_t *ctx = conn->io_ctx;

    switch(conn->state)
    {
        case ASIO_TASK_RUNNING:
            if (ctx->callback(conn, ctx->cb_arg, conn->user_data) != ASIO_OK) {
                conn->task_flags |= TASK_FLAG_TERMINATE;
            }
            break;

        case ASIO_TASK_STOPPING:
        case ASIO_TASK_STOPPED:
            asio_generic_destroy(conn);
            break;

        default:
            break;
    }

    return ASIO_OK;
}


asio_connection_t *asio_new_generic_task(asio_registry_t *registry, asio_generic_callback_t callback, void *cb_arg, void *user_data)
{
    asio_connection_t *conn = calloc(1, sizeof(asio_connection_t));
    if(conn == NULL) {
        ESP_LOGE(TAG, "calloc() failed: asio_connection_t");
        return NULL;
    }

    conn->registry = registry;
    conn->io_handler = asio_generic_handler;
    conn->state = ASIO_TASK_RUNNING;
    conn->user_data = user_data;

    asio_generic_ctx_t *generic_ctx = calloc(1, sizeof(asio_generic_ctx_t));
    conn->io_ctx = generic_ctx;
    generic_ctx->callback = callback;
    generic_ctx->cb_arg = cb_arg;

    if(asio_registry_add_connection(registry, conn) < 0) {
        ESP_LOGE(TAG, "failed to add connection");
        asio_registry_remove_connection(conn);
        return NULL;
    }

    return conn;
}
