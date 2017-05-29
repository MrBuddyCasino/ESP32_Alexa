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
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include "http_parser.h"


#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif


/* underlying ssl connection */
typedef struct
{
    mbedtls_ssl_context *ssl_context;
    mbedtls_net_context *server_fd;
    /* only referenced here to simply cleanup */
    mbedtls_ssl_config *conf;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_entropy_context *entropy;
} ssl_session_data_t;


/* the http2 session
 * can have multiple associated streams
 */
typedef struct
{
    /* nghttp2_session is hidden */
    nghttp2_session *h2_session;

    /* underlying connection */
    ssl_session_data_t *ssl_session;

    /* underlying connection */
    void *conn;

    /* current number of outgoing streams because
     * session_data->nghttp2_session->num_outgoing_streams is private
     */
    uint8_t num_outgoing_streams;

    /* your place */
    void *user_data;

} http2_session_data_t;

void free_http2_session_data(http2_session_data_t *session_data, int ret);

/**
 * @brief create a new session
 */
int nghttp_new_session(http2_session_data_t **http2_session_ptr,
                    char *uri, char *method,
                    int32_t *stream_id,
                    nghttp2_nv *headers,  size_t hdr_len,
                    nghttp2_data_provider *data_provider_struct,
                    nghttp2_session_callbacks *callbacks,
                    void *stream_user_data,
                    void *session_user_data);

/**
 * @brief create a new stream for an existing session
 */
int nghttp_new_stream(http2_session_data_t *http2_session,
        int32_t *stream_id,
        void *stream_user_data,
        char *uri, char *method,
        nghttp2_nv *headers,  size_t hdr_len,
        nghttp2_data_provider *data_provider_struct);


void event_loop_task(void *pvParameters);
int read_write_loop(http2_session_data_t* http2_session);

int create_default_callbacks(nghttp2_session_callbacks **callbacks_ptr);

#endif /* COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_ */
