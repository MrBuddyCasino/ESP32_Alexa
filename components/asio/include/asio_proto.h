/*
 * asio_proto.h
 *
 *  Created on: 23.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_PROTO_H_
#define _INCLUDE_ASIO_PROTO_H_

typedef struct {
    char *key;
    char *value;
} http_header_t;

int asio_http_request(asio_registry_t *registry, char *uri, char *method, http_header_t headers[], uint16_t header_len, http_parser_settings *callbacks, asio_event_handler_t cb, void *user_data);

#endif /* _INCLUDE_ASIO_PROTO_H_ */
