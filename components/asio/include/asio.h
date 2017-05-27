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

typedef enum
{
    ASIO_EVT_NEW = 1, ASIO_EVT_CONNECTED, ASIO_EVT_CLOSE, ASIO_EVT_SOCKET_READY
} asio_event_t;


typedef enum {
    ASIO_CB_OK = 1, ASIO_CB_ERR, ASIO_CB_CLOSE_CONNECTION
} asio_cb_res_t;


typedef enum {
    ASIO_POLL_OK = 1, ASIO_POLL_ERR
} asio_poll_res_t;


typedef enum
{
    ASIO_TCP = 1
} asio_transport_t;


typedef enum
{
    ASIO_CONN_NEW = 1,
    ASIO_CONN_CONNECTING,
    ASIO_CONN_CONNECTED,
    ASIO_CONN_CLOSED
} asio_conn_state_t;


typedef struct asio_connection_t asio_connection_t;
typedef struct asio_registry_t asio_registry_t;


typedef asio_cb_res_t (*asio_event_handler_t)(struct asio_connection_t *conn, asio_event_t event, void *user_data);

typedef asio_poll_res_t (*asio_poll_t)(asio_connection_t *conn);

struct asio_connection_t
{
    asio_registry_t *registry;
    url_t *url;
    int fd;
    bool is_buffered;
    asio_transport_t transport;
    asio_conn_state_t state;
    asio_event_handler_t evt_handler;
    void *proto_ctx;
    asio_event_handler_t proto_handler;
    void *user_data;
    buffer_t *recv_buf;
    buffer_t *send_buf;
    int user_flags;
    int poll_flags;
    asio_poll_t poll_handler;
    asio_event_handler_t io_handler;
    void *io_ctx;
};


struct asio_registry_t
{
    uint16_t max_connections;
    asio_connection_t *connections[16];
    void *user_data;
};

int asio_registry_poll(asio_registry_t *registry);

void asio_registry_init(asio_registry_t **registry, void *user_data);

void asio_registry_destroy(asio_registry_t *registry);

int asio_registry_add_connection(asio_registry_t *registry, asio_connection_t *connection);

void asio_registry_remove_connection(asio_connection_t *conn);

#endif /* _INCLUDE_EVENT_LOOP_H_ */
