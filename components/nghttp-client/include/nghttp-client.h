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

#include "nghttp2/nghttp2.h"


/*
 * user data that is associated with a stream
 * retrieve with:
 * void * nghttp2_session_get_stream_user_data(nghttp2_session *session, int32_t stream_id)
 */
typedef struct
{
    /* The NULL-terminated URI string to retrieve. */
    char *uri;

    /* The host portion of the |uri|, NULL-terminated */
    char *host;

    /* The schema portion of the |uri|, NULL-terminated */
    char *scheme;

    /* The port portion of the |uri|, or the schema's default port */
    uint16_t port;

    /* The authority portion of the |uri|, NULL-terminated */
    char *authority;

    /* The path portion of the |uri|, including query, NULL-terminated */
    char *path;

} http2_request_data;


/* underlying ssl connection */
typedef struct
{
    mbedtls_ssl_context *ssl_context;
    mbedtls_net_context *server_fd;
} ssl_session_data;


/* the http2 session
 * can have multiple associated streams
 */
typedef struct
{
    /* details all hidden */
    nghttp2_session *session;
    http2_request_data *request_data;
    ssl_session_data *ssl_session;
    int32_t num_outgoing_streams;
} http2_session_data;



esp_err_t nghttp_get(char *uri);

esp_err_t nghttp_post(char *uri, nghttp2_data_provider *data_provider_struct);
esp_err_t nghttp_put(char *uri, nghttp2_data_provider *data_provider_struct);


#endif /* COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_ */
