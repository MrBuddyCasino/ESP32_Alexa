/*
 * asio_socket.h
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_SOCKET_H_
#define _INCLUDE_ASIO_SOCKET_H_

typedef enum
{
    ASIO_TCP = 1, ASIO_TCP_SSL = 2
} asio_transport_t;

enum poll_flags
{
    POLL_FLAG_RECV  = 1 << 0
  , POLL_FLAG_SEND  = 1 << 1
  , POLL_FLAG_ERR   = 1 << 2
};

/* I/O context for sockets */
typedef struct {
    buffer_t *recv_buf;
    buffer_t *send_buf;
    int fd;
    int poll_flags;
} asio_socket_context_t;


/* connect a socket */
int asio_socket_connect(const char *host, uint16_t port, bool verbose);

/* poll handler for socket connection */
asio_result_t asio_socket_poll(asio_connection_t *conn);

/* create a new plaintext socket connection */
asio_connection_t *asio_new_socket_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, void *user_data);

#endif /* _INCLUDE_ASIO_SOCKET_H_ */
