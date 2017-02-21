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


typedef struct
{
    /* The NULL-terminated URI string to retrieve. */
    const char *uri;
    /* Parsed result of the |uri| */
    struct http_parser_url *u;
    /* The authority portion of the |uri|, not NULL-terminated */
    char *authority;
    /* The path portion of the |uri|, including query, not
     NULL-terminated */
    char *path;
    /* The length of the |authority| */
    size_t authoritylen;
    /* The length of the |path| */
    size_t pathlen;
    /* The stream ID of this stream */
    int32_t stream_id;
} http2_stream_data;


typedef struct
{
    mbedtls_ssl_context *ssl_context;
    mbedtls_net_context *server_fd;
} ssl_session_data;


typedef struct
{
    nghttp2_session *session;
    http2_stream_data *stream_data;
    ssl_session_data *ssl_session;
} http2_session_data;



esp_err_t nghttp_get(const char *uri);


#endif /* COMPONENTS_NGHTTP_NGHTTP_CLIENT_H_ */
