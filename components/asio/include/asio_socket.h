/*
 * asio_socket.h
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_SOCKET_H_
#define _INCLUDE_ASIO_SOCKET_H_

int asio_socket_connect(const char *host, uint16_t port, int verbose);

/* poll handler for socket connection */
asio_poll_res_t asio_socket_poll(asio_connection_t *conn, int *flags);


asio_connection_t *asio_new_socket_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, void *user_data);

asio_connection_t *asio_new_ssl_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, int bidi, char *alpn, cipher_suite *suites, size_t num_suites, void *user_data);

#endif /* _INCLUDE_ASIO_SOCKET_H_ */
