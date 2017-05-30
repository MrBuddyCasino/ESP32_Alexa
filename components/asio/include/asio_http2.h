/*
 * asio_http2.h
 *
 *  Created on: 28.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_HTTP2_H_
#define _INCLUDE_ASIO_HTTP2_H_

int asio_new_http2_session(
        asio_registry_t *registry,
        http2_session_data_t *http2_session_ptr,
        char *uri);

int asio_http2_on_stream_close(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data);

void asio_test_http2();

#endif /* _INCLUDE_ASIO_HTTP2_H_ */
