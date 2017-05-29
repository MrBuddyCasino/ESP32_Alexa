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
        http2_session_data_t **http2_session_ptr,
        char *uri, char *method,
        int32_t *stream_id,
        nghttp2_nv *headers,  size_t hdr_len,
        nghttp2_data_provider *data_provider_struct,
        nghttp2_session_callbacks *callbacks,
        void *stream_user_data,
        void *session_user_data);

void asio_test_http2();

#endif /* _INCLUDE_ASIO_HTTP2_H_ */
