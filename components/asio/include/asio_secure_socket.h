/*
 * asio_secure_socket.h
 *
 *  Created on: 02.06.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_SECURE_SOCKET_H_
#define _INCLUDE_ASIO_SECURE_SOCKET_H_

/* create an encrypted socket connection */
asio_task_t *asio_new_ssl_connection(asio_registry_t *registry, asio_transport_t transport_proto, char *uri, int bidi, char *alpn, cipher_suite *suites, size_t num_suites, void *user_data);

#endif /* _INCLUDE_ASIO_SECURE_SOCKET_H_ */
