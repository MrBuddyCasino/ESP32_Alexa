/*
 * event_loop.h
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_EVENT_LOOP_H_
#define _INCLUDE_EVENT_LOOP_H_

enum task_flags {
    TASK_FLAG_NONE  = 1 << 0
  , TASK_FLAG_TERMINATE = 1 << 1
};


typedef enum {
    ASIO_OK = 0, ASIO_ERR = -1
} asio_result_t;


typedef enum
{
    ASIO_TASK_NEW = 1,
    ASIO_TASK_STARTING,
    ASIO_TASK_RUNNING,
    ASIO_TASK_STOPPING,
    ASIO_TASK_STOPPED
} asio_conn_state_t;


typedef struct asio_connection_t asio_connection_t;
typedef struct asio_registry_t asio_registry_t;


typedef asio_result_t (*asio_event_handler_t)(struct asio_connection_t *conn);


/* app send/recv data */
typedef size_t (*asio_on_data_transfer_t) (asio_connection_t *conn, unsigned char* buf, size_t len);


struct asio_connection_t
{
    asio_registry_t *registry;
    url_t *url;
    asio_conn_state_t state;
    asio_event_handler_t evt_handler;
    void *user_data;
    int task_flags;

    asio_event_handler_t io_handler;
    void *io_ctx;

    void *proto_ctx;
    asio_event_handler_t proto_handler;

    time_t last_modified;

    /* send data to app */
    asio_on_data_transfer_t app_recv;

    /* get data from app */
    asio_on_data_transfer_t app_send;
};


struct asio_registry_t
{
    uint16_t max_connections;
    asio_connection_t *connections[16];
    void *user_data;
};

/* poll all connections and execute callbacks */
int asio_registry_poll(asio_registry_t *registry);

void asio_registry_init(asio_registry_t **registry, void *user_data);

void asio_registry_destroy(asio_registry_t *registry);

int asio_registry_add_connection(asio_registry_t *registry, asio_connection_t *connection);

void asio_registry_remove_connection(asio_connection_t *conn);

#endif /* _INCLUDE_EVENT_LOOP_H_ */
