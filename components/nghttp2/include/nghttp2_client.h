/*
 * nghttp-client.h
 *
 *  Created on: 26.01.2017
 *      Author: michaelboeckling
 */

#ifndef COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_
#define COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_

#include "esp_err.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"

#include "http_parser.h"


/* underlying ssl connection */
typedef struct
{
    mbedtls_ssl_context *ssl_context;
    mbedtls_net_context *server_fd;
    /* only referenced here to simply cleanup */
    mbedtls_ssl_config *conf;
} ssl_session_data;


/* the http2 session
 * can have multiple associated streams
 */
typedef struct
{
    /* nghttp2_session is hidden */
    nghttp2_session *nghttp2_session;

    /* underlying connection */
    ssl_session_data *ssl_session;

    /* current number of outgoing streams */
    uint8_t num_outgoing_streams;

    /* your place */
    void *session_user_data;

} http2_session_data_t;

void free_http2_session_data(http2_session_data_t *session_data, int ret);

/**
 * @brief create a new session
 */
int nghttp_new_session(http2_session_data_t **http2_session_ptr,
                    char *uri, char *method,
                    nghttp2_nv *headers,  size_t hdr_len,
                    nghttp2_data_provider *data_provider_struct,
                    nghttp2_session_callbacks *callbacks,
                    void *stream_user_data,
                    void *session_user_data);

/**
 * @brief create a new stream for an existing session
 */
int nghttp_new_stream(http2_session_data_t *http2_session,
        void *stream_user_data,
        char *uri, char *method,
        nghttp2_nv *headers,  size_t hdr_len,
        nghttp2_data_provider *data_provider_struct);


void event_loop_task(void *pvParameters);
int read_write_loop(nghttp2_session *session, mbedtls_ssl_context *ssl_context);

int create_default_callbacks(nghttp2_session_callbacks **callbacks_ptr);

#endif /* COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_ */
