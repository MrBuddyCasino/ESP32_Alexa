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

#include "esp_system.h"
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
    (*registry)->max_tasks = 16;
}

void asio_registry_destroy(asio_registry_t *registry)
{
    for (int i = 0; i < registry->max_tasks; i++) {
        if (registry->tasks[i] != NULL) {
            asio_registry_remove_task(registry->tasks[i]);
            registry->tasks[i] = NULL;
        }
    }

    free(registry);
}

int asio_registry_add_task(asio_registry_t *registry, asio_task_t *task)
{
    if(task->url) {
        ESP_LOGI(TAG, "adding connection: %s", task->url->authority);
    }

    for (int i = 0; i < registry->max_tasks; i++) {
        if (registry->tasks[i] == NULL) {
            registry->tasks[i] = task;
            return 0;
        }
    }

    return -1;
}

void asio_registry_remove_task(asio_task_t *conn)
{
    if(conn == NULL) return;

    if(conn->url) {
        ESP_LOGI(TAG, "removing connection: %s", conn->url->authority);
    }

    asio_registry_t *registry = conn->registry;
    for (int i = 0; i < registry->max_tasks; i++) {
        if (registry->tasks[i] == conn) {
            registry->tasks[i] = NULL;
            break;
        }
    }

    free(conn->proto_ctx);
    free(conn->io_ctx);
    url_free(conn->url);
    free(conn);

    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
}


static void asio_registry_poll_connection(asio_registry_t *registry, asio_task_t *task)
{
    asio_result_t cb_res;

    // perform I/O
    task->io_handler(task);

    // notify proto
    if(task->proto_handler) {
        task->proto_handler(task);
    }

    // notify user
    if(task->evt_handler) {
        task->evt_handler(task);
    }

    if(task->task_flags & TASK_FLAG_TERMINATE) {
        task->state = ASIO_TASK_STOPPING;
        task->task_flags = 0;
    }

    // connection was closing last round, now its time to say goodbye
    if(task->state == ASIO_TASK_STOPPING) {

        task->io_handler(task);

        if(task->proto_handler) {
            task->proto_handler(task);
        }

        if(task->evt_handler) {
            task->evt_handler(task);
        }

        task->state = ASIO_TASK_STOPPED;
    }

    // all handlers have been notified thats its game over, remove
    if(task->state == ASIO_TASK_STOPPED) {
        asio_registry_remove_task(task);
    }

}

int asio_registry_poll(asio_registry_t *registry)
{
    uint8_t num_conn = 0;
    for (int i = 0; i < registry->max_tasks; i++) {
        asio_task_t *conn = registry->tasks[i];
        if (conn == NULL) continue;

        asio_registry_poll_connection(registry, conn);
        num_conn++;
    }

    return num_conn;
}

