/*
 * event_loop.h
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_EVENT_LOOP_H_
#define _INCLUDE_EVENT_LOOP_H_


enum poll_flags
{
    POLL_FLAG_RECV  = 1 << 0
  , POLL_FLAG_SEND  = 1 << 1
  , POLL_FLAG_ERR   = 1 << 2
};

enum conn_flags {
    CONN_FLAG_NONE  = 1 << 0
  , CONN_FLAG_CLOSE = 1 << 1
};


typedef enum {
    ASIO_OK = 0, ASIO_ERR = -1, ASIO_CLOSE_CONNECTION = -2
} asio_result_t;


typedef enum
{
    ASIO_TCP = 1, ASIO_TCP_SSL = 2
} asio_transport_t;


typedef enum
{
    ASIO_CONN_NEW = 1,
    ASIO_CONN_CONNECTING,
    ASIO_CONN_CONNECTED,
    ASIO_CONN_CLOSING,
    ASIO_CONN_CLOSED
} asio_conn_state_t;


typedef struct asio_connection_t asio_connection_t;
typedef struct asio_registry_t asio_registry_t;


typedef asio_result_t (*asio_event_handler_t)(struct asio_connection_t *conn);

typedef asio_result_t (*asio_poll_t)(asio_connection_t *conn);

/* app send/recv data */
typedef size_t (*asio_on_data_transfer_t) (asio_connection_t *conn, unsigned char* buf, size_t len);

struct asio_connection_t
{
    asio_registry_t *registry;
    url_t *url;
    int fd;
    asio_transport_t transport;
    asio_conn_state_t state;
    asio_event_handler_t evt_handler;
    void *proto_ctx;
    asio_event_handler_t proto_handler;
    void *user_data;
    int user_flags;
    int poll_flags;
    asio_poll_t poll_handler;
    asio_event_handler_t io_handler;
    void *io_ctx;

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
