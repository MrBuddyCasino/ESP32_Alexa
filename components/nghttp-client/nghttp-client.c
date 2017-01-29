/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef __sgi
#include <string.h>
char *strndup(const char *s, size_t size);
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <lwip/tcp.h>
#ifndef __sgi
#include <lwip/err.h>
#endif
#include <signal.h>
#include <string.h>

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "esp_err.h"
#include "esp_log.h"

#include "nghttp2/nghttp2.h"

#include "http_parser.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define TAG "nghttp2"

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
    nghttp2_session *session;
    http2_stream_data *stream_data;
    mbedtls_ssl_context *ssl;
    mbedtls_net_context *server_fd;
} http2_session_data;

#ifdef MBEDTLS_DEBUG_C

#define MBEDTLS_DEBUG_LEVEL 4

/* mbedtls debug function that translates mbedTLS debug output
 to ESP_LOGx debug output.

 MBEDTLS_DEBUG_LEVEL 4 means all mbedTLS debug output gets sent here,
 and then filtered to the ESP logging mechanism.
 */
static void mbedtls_debug(void *ctx, int level, const char *file, int line,
        const char *str)
{
    const char *MBTAG = "mbedtls";
    char *file_sep;

    /* Shorten 'file' from the whole file path to just the filename

     This is a bit wasteful because the macros are compiled in with
     the full _FILE_ path in each case.
     */
    file_sep = rindex(file, '/');
    if (file_sep) file = file_sep + 1;

    switch (level) {
        case 1:
            ESP_LOGI(MBTAG, "%s:%d %s", file, line, str);
            break;
        case 2:
        case 3:
            ESP_LOGD(MBTAG, "%s:%d %s", file, line, str);
            break;
        case 4:
            ESP_LOGV(MBTAG, "%s:%d %s", file, line, str);
            break;
        default:
            ESP_LOGE(MBTAG, "Unexpected log level %d: %s", level, str);
            break;
    }
}

#endif




/* cleanup mbedtls */
void destroy_mbedtls_context(mbedtls_ssl_context *ssl,
        mbedtls_net_context *server_fd, int ret)
{
    mbedtls_ssl_session_reset(ssl);
    mbedtls_net_free(server_fd);

    if (ret != 0) {
        char* buf = calloc(100, sizeof(char));
        mbedtls_strerror(ret, buf, 100);
        ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        free(buf);
    }
}



static http2_stream_data *create_http2_stream_data(const char *uri,
        struct http_parser_url *u)
{
    /* MAX 5 digits (max 65535) + 1 ':' + 1 NULL (because of snprintf) */
    size_t extra = 7;
    http2_stream_data *stream_data = malloc(sizeof(http2_stream_data));

    stream_data->uri = uri;
    stream_data->u = u;
    stream_data->stream_id = -1;

    stream_data->authoritylen = u->field_data[UF_HOST].len;
    stream_data->authority = malloc(stream_data->authoritylen + extra);
    memcpy(stream_data->authority, &uri[u->field_data[UF_HOST].off],
            u->field_data[UF_HOST].len);
    if (u->field_set & (1 << UF_PORT)) {
        stream_data->authoritylen += (size_t) snprintf(
                stream_data->authority + u->field_data[UF_HOST].len, extra,
                ":%u", u->port);
    }

    /* If we don't have path in URI, we use "/" as path. */
    stream_data->pathlen = 1;
    if (u->field_set & (1 << UF_PATH)) {
        stream_data->pathlen = u->field_data[UF_PATH].len;
    }
    if (u->field_set & (1 << UF_QUERY)) {
        /* +1 for '?' character */
        stream_data->pathlen += (size_t) (u->field_data[UF_QUERY].len + 1);
    }

    stream_data->path = malloc(stream_data->pathlen);
    if (u->field_set & (1 << UF_PATH)) {
        memcpy(stream_data->path, &uri[u->field_data[UF_PATH].off],
                u->field_data[UF_PATH].len);
    } else {
        stream_data->path[0] = '/';
    }
    if (u->field_set & (1 << UF_QUERY)) {
        stream_data->path[stream_data->pathlen - u->field_data[UF_QUERY].len - 1] =
                '?';
        memcpy(
                stream_data->path + stream_data->pathlen
                        - u->field_data[UF_QUERY].len,
                &uri[u->field_data[UF_QUERY].off], u->field_data[UF_QUERY].len);
    }

    return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data)
{
    free(stream_data->path);
    free(stream_data->authority);
    free(stream_data);
}

/* Initializes |session_data| */
static http2_session_data *create_http2_session_data()
{
    http2_session_data *session_data = malloc(sizeof(http2_session_data));

    memset(session_data, 0, sizeof(http2_session_data));
    // session_data->dnsbase = evdns_base_new(evbase, 1);
    return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data)
{

    if (session_data->ssl) {
        destroy_mbedtls_context(session_data->ssl, session_data->server_fd, 0);
    }

    nghttp2_session_del(session_data->session);
    session_data->session = NULL;
    if (session_data->stream_data) {
        delete_http2_stream_data(session_data->stream_data);
        session_data->stream_data = NULL;
    }
    free(session_data);
}

static void print_header(const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen)
{
    printf("%s: %s\n", name, value);
}

/* Print HTTP headers to |f|. Please note that this function does not
 take into account that header name and value are sequence of
 octets, therefore they may contain non-printable characters. */
static void print_headers(nghttp2_nv *nva, size_t nvlen)
{
    size_t i;
    for (i = 0; i < nvlen; ++i) {
        print_header(nva[i].name, nva[i].namelen, nva[i].value,
                nva[i].valuelen);
    }
    printf("\n");
}

/* nghttp2_send_callback. Here we transmit the |data|, |length| bytes,
 to the network. */
static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
        size_t length, int flags, void *user_data)
{
    int ret;
    http2_session_data *session_data = (http2_session_data *) user_data;

    mbedtls_ssl_context *ssl = session_data->ssl;
    mbedtls_net_context *server_fd = session_data->server_fd;

    while((ret = mbedtls_ssl_write(ssl, data, length)) <= 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            destroy_mbedtls_context(ssl, server_fd, ret);
            return ret;
        }
    }

    return (ssize_t) ret;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
 single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
        const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE
                    && session_data->stream_data->stream_id
                            == frame->hd.stream_id) {
                /* Print response headers for the initiated request. */
                print_header(name, namelen, value, valuelen);
                break;
            }
    }
    return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
 started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
        const nghttp2_frame *frame, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE
                    && session_data->stream_data->stream_id
                            == frame->hd.stream_id) {
                ESP_LOGI(TAG, "Response headers for stream ID=%d:\n",
                        frame->hd.stream_id);
            }
            break;
    }
    return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
 received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session,
        const nghttp2_frame *frame, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE
                    && session_data->stream_data->stream_id
                            == frame->hd.stream_id) {
                ESP_LOGI(TAG, "All headers received");
            }
            break;
    }
    return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
 received from the remote peer. In this implementation, if the frame
 is meant to the stream we initiated, print the received data in
 stdout, so that the user can redirect its output to the file
 easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    if (session_data->stream_data->stream_id == stream_id) {
        // printf("received %d bytes", len);
        printf("%.*s", len, data);
    }
    return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
 closed. This example program only deals with 1 HTTP request (1
 stream), if it is closed, we send GOAWAY and tear down the
 session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    int rv;

    if (session_data->stream_data->stream_id == stream_id) {
        ESP_LOGE(TAG, "Stream %d closed with error_code=%u\n", stream_id,
                error_code);
        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if (rv != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}


/**
 *  *session_data is our handle
 */
static void initialize_nghttp2_session(http2_session_data *session_data)
{
    nghttp2_session_callbacks *callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    // Here we transmit the data to the network.
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
            on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
            on_data_chunk_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
            on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
            on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
            on_begin_headers_callback);

    nghttp2_session_client_new(&session_data->session, callbacks, session_data);

    nghttp2_session_callbacks_del(callbacks);
}

static esp_err_t send_client_connection_header(http2_session_data *session_data)
{
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            100 } };

    /* client 24 bytes magic string will be sent by nghttp2 library */
    int rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
            ARRLEN(iv));
    if (rv != 0) {
        ESP_LOGE(TAG, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
        return ESP_FAIL;
    }
    return ESP_OK;
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

/* Send HTTP request to the remote peer */
static esp_err_t submit_request(http2_session_data *session_data)
{
    int32_t stream_id;
    http2_stream_data *stream_data = session_data->stream_data;
    const char *uri = stream_data->uri;
    const struct http_parser_url *u = stream_data->u;
    nghttp2_nv hdrs[] = {
    MAKE_NV2(":method", "GET"),
    MAKE_NV(":scheme", &uri[u->field_data[UF_SCHEMA].off],
            u->field_data[UF_SCHEMA].len),
    MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
    MAKE_NV(":path", stream_data->path, stream_data->pathlen) };
    ESP_LOGI(TAG, "Request headers:");
    print_headers(hdrs, ARRLEN(hdrs));

    stream_id = nghttp2_submit_request(session_data->session, NULL, hdrs,
            ARRLEN(hdrs), NULL, stream_data);

    if (stream_id < 0) {
        ESP_LOGE(TAG, "Could not submit HTTP request: %s",
                nghttp2_strerror(stream_id));
        return ESP_FAIL;
    }

    stream_data->stream_id = stream_id;
    return ESP_OK;
}

/* Serialize the frame and send (or buffer) the data to
 bufferevent. */
static esp_err_t session_send(http2_session_data *session_data)
{
    int rv = nghttp2_session_send(session_data->session);
    if (rv != 0) {
        ESP_LOGE(TAG, "Fatal error: %s", nghttp2_strerror(rv));
        return ESP_FAIL;
    }

    return ESP_OK;
}




/* Get resource denoted by the |uri|. The debug and error messages are
 printed in stderr, while the response body is printed in stdout. */
esp_err_t nghttp_get(const char *uri)
{
    struct http_parser_url url;
    char *host;
    uint16_t port;
    int rv;

    http2_session_data *session_data;

    /* Parse the |uri| and stores its components in |url| */
    rv = http_parser_parse_url(uri, strlen(uri), 0, &url);
    if (rv != 0) {
        ESP_LOGE(TAG, "Could not parse URI %s", uri);
        return ESP_FAIL;
    }

    host = strndup(&uri[url.field_data[UF_HOST].off], url.field_data[UF_HOST].len);
    if (!(url.field_set & (1 << UF_PORT))) {
        port = 443;
    } else {
        port = url.port;
    }


    /* init ssl */
    uint8_t buf[512];
    int ret;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    // alpn
    const char *alpn_list[2];
    memset( (void * ) alpn_list, 0, sizeof( alpn_list ) );
    alpn_list[0] = "h2";
    alpn_list[1] = NULL;


    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        return ESP_FAIL;
    }

    // alpn
    if( ( ret = mbedtls_ssl_conf_alpn_protocols( &conf, alpn_list ) ) != 0 )
     {
         mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_alpn_protocols returned %d\n\n", ret );
         destroy_mbedtls_context(&ssl, &server_fd, ret);
         return ESP_FAIL;
     }

    /*
     ESP_LOGI(TAG, "Loading the CA root certificate...");

     ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
     server_root_cert_pem_end-server_root_cert_pem_start);

    if (ret < 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        return ESP_FAIL;
    }
    */

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    /* Hostname set here should match CN in server certificate */
    if ((ret = mbedtls_ssl_set_hostname(&ssl, host)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(&conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        destroy_mbedtls_context(&ssl, &server_fd, ret);
        return ESP_FAIL;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
     a warning if CA verification fails but it will continue to connect.

     You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
     */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(&conf, mbedtls_debug, NULL);
#endif

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        destroy_mbedtls_context(&ssl, &server_fd, ret);
        return ESP_FAIL;
    }

    /* wifi must be up from this point on */

    mbedtls_net_init(&server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%" PRIu16 "...", host, port);

    // convert port to string
    char port_str[6];
    itoa(port, (char*) &port_str, 10);

    // ret = mbedtls_net_connect(&server_fd, (const char *) &host,
    //            (const char *) &port_str, MBEDTLS_NET_PROTO_TCP);
    ret = mbedtls_net_connect(&server_fd, "http2.golang.org",
                   "443", MBEDTLS_NET_PROTO_TCP);

    if (ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        destroy_mbedtls_context(&ssl, &server_fd, ret);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            destroy_mbedtls_context(&ssl, &server_fd, ret);
            return ESP_FAIL;
        }
    }

    // alpn
    const char *alp = mbedtls_ssl_get_alpn_protocol( &ssl );
    mbedtls_printf( "    [ Application Layer Protocol is %s ]\n", alp ? alp : "(none)" );


    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0)
    {
        /* In real life, we probably want to close connection if ret != 0 */
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info((char *) buf, sizeof(buf), "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
    }
    else
    {
        ESP_LOGI(TAG, "Certificate verified.");
    }

    ESP_LOGI(TAG, "Writing HTTP request...");

    session_data = create_http2_session_data();
    session_data->stream_data = create_http2_stream_data(uri, &url);


    /* connection established */

    // set mbedtls fields
    session_data->ssl = &ssl;
    session_data->server_fd = &server_fd;

    // register callbacks
    initialize_nghttp2_session(session_data);

    // send request
    send_client_connection_header(session_data);
    submit_request(session_data);
    if (session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
    }


    /* Read HTTP response */

    bzero(buf, sizeof(buf));
    ssize_t datalen;
    esp_err_t cont = ESP_OK;

    do {
        ret = mbedtls_ssl_read( &ssl, buf, sizeof(buf) - 1 );

        if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // continue;
        }

        if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            ret = 0;
            break;
        }

        if(ret < 0)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
            break;
        }

        if(ret == 0)
        {
            ESP_LOGI(TAG, "connection closed");
            break;
        }

        datalen = ret;
        ESP_LOGI(TAG, "%d bytes read", datalen);

        // print received data
        // printf("%.*s", datalen, buf);

        // cont = (*callback)(recv_buf, datalen);

        ssize_t readlen = nghttp2_session_mem_recv(session_data->session,
                buf, datalen);

        if (readlen < 0) {
            ESP_LOGW(TAG, "Fatal error: %s", nghttp2_strerror((int ) readlen));
            delete_http2_session_data(session_data);
            cont = ESP_FAIL;
        }

        // if we have data to send, do it here
        if (session_send(session_data) != 0) {
            delete_http2_session_data(session_data);
            cont = ESP_FAIL;
        }

    } while (ret > 0 && cont == ESP_OK);

    delete_http2_session_data(session_data);

    free(host);
    host = NULL;

    return ESP_OK;
}

