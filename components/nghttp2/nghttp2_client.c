
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
#include <stdint.h>


typedef time_t mbedtls_time_t;

#include "mbedtls/debug.h"
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

#include "esp_system.h"
#include "esp_err.h"
#include "esp_log.h"

#include "nghttp2/nghttp2.h"
#include "http_parser.h"
#include "url_parser.h"

#include "nghttp2_client.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define TAG "nghttp2"



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
            ESP_LOGD(MBTAG, "%s:%d %s", file, line, str);
            break;
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



/* Initializes |session_data| */
static esp_err_t alloc_http2_session_data(http2_session_data_t **session_data_ptr)
{
    *session_data_ptr = calloc(1, sizeof(http2_session_data_t));
    if((*session_data_ptr) == NULL) {
        ESP_LOGE(TAG, "http2_session_data malloc failed");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t free_ssl_session_data(ssl_session_data_t *session, int32_t ret)
{
    if(session == NULL)
        return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "freeing ssl_session_data");

    mbedtls_ssl_free(session->ssl_context);
    mbedtls_free(session->ssl_context);

    mbedtls_net_free(session->server_fd);
    mbedtls_free(session->server_fd);

    mbedtls_ssl_config_free(session->conf);
    mbedtls_ctr_drbg_free(session->ctr_drbg);
    mbedtls_entropy_free(session->entropy);

    free(session);

    if (ret != 0) {
        char* buf = calloc(100, sizeof(char));
        if(buf == NULL) {
            return ESP_ERR_NO_MEM;
        }
        mbedtls_strerror(ret, buf, 100);
        ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        free(buf);
    }

    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    return ESP_OK;
}


void free_http2_session_data(http2_session_data_t *session_data, int ret)
{

    if (session_data->ssl_session) {
        // shutdown SSL
        free_ssl_session_data(session_data->ssl_session, ret);
    }

    ESP_LOGI(TAG, "freeing http2_session_data");
    nghttp2_session_del(session_data->h2_session);

    free(session_data);

    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
}

static void print_header(const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen)
{
    ESP_LOGI(TAG, "%s: %s", name, value);
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
static ssize_t on_send_callback(nghttp2_session *session, const uint8_t *data,
                                size_t length, int flags, void *user_data)
{

    ssize_t ret;
    http2_session_data_t *session_data = (http2_session_data_t *) user_data;

    // ESP_LOGE(TAG, "entered on_send_callback, writing %d bytes", length);
    while((ret = mbedtls_ssl_write(session_data->ssl_session->ssl_context, data, length)) <= 0)
    {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            return ret;
        }
    }

    return ret;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
 single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
        const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    // http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
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
    // http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                ESP_LOGI(TAG, "Response headers for stream ID=%d:",
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
    // frame->hd.flags & NGHTTP2_FLAG_END_STREAM

    // http2_session_data *session_data = (http2_session_data *) user_data;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            print_headers(frame->headers.nva, frame->headers.nvlen);
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                ESP_LOGI(TAG, "All headers received");
            }
            break;

        case NGHTTP2_GOAWAY:
            // TODO
            break;

        default:
            ESP_LOGI(TAG, "frame received: %u", frame->hd.type);
            break;

    }
    return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
 received from the remote peer. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    // http2_session_data *session_data = (http2_session_data *) user_data;
    ESP_LOGI(TAG, "%.*s", len, data);

    return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
 closed. If the last stream is closed, we send GOAWAY and tear down the
 session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);

    return 0;
}


/* fixes assertion error in:
 * assert(nghttp2_buf_avail(buf) >= datamax);
 */
ssize_t on_data_source_read_length_callback (
    nghttp2_session *session, uint8_t frame_type, int32_t stream_id,
    int32_t session_remote_window_size, int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size, void *user_data)
{
    ssize_t len = 2048; // 8192
    len = min(len, session_remote_window_size);
    len = min(len, stream_remote_window_size);
    len = min(len, remote_max_frame_size);

    return len;
}


int create_default_callbacks(nghttp2_session_callbacks **callbacks_ptr)
{
    if((nghttp2_session_callbacks_new(callbacks_ptr)) == NGHTTP2_ERR_NOMEM) {
        ESP_LOGE(TAG, "failed to allocate nghttp2_session_callbacks");
        return NGHTTP2_ERR_NOMEM;
    }

    nghttp2_session_callbacks *callbacks = (*callbacks_ptr);

    // Here we transmit the data to the network.
    nghttp2_session_callbacks_set_send_callback(callbacks, on_send_callback);

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

    // optional: send buffer size
    nghttp2_session_callbacks_set_data_source_read_length_callback(callbacks,
            on_data_source_read_length_callback);

    return 0;
}

/**
 *  *session_data is our handle
 */
static int register_session_callbacks(nghttp2_session **session_ptr, nghttp2_session_callbacks *callbacks, void *user_data)
{
    int ret = 0;

    ret = nghttp2_session_client_new(session_ptr, callbacks, user_data);
    nghttp2_session_callbacks_del(callbacks);

    return ret;
}

static esp_err_t send_client_connection_header(nghttp2_session *session)
{
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
            10 } };

    /* client 24 bytes magic string will be sent by nghttp2 library */
    int rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv,
            ARRLEN(iv));
    if (rv != 0) {
        ESP_LOGE(TAG, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
        return rv;
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
static esp_err_t submit_request(http2_session_data_t *session_data,
        const url_t *url,
        const nghttp2_nv *user_hdrs, size_t user_hdr_len,
        const char* method,
        const nghttp2_data_provider *data_prd,
        void* stream_user_data)
{

    int32_t stream_id;

    /* create pseudo-headers */
    nghttp2_nv default_hdrs[] = {
        MAKE_NV(":method",      method,        strlen(method)),
        MAKE_NV(":scheme",      url->scheme,   strlen(url->scheme)),
        MAKE_NV(":authority",   url->authority,strlen(url->authority)),
        MAKE_NV(":path",        url->path,     strlen(url->path))
    };

    /* combine with user headers */
    nghttp2_nv hdrs[ARRLEN(default_hdrs) + user_hdr_len];

    for(int i = 0; i < ARRLEN(default_hdrs); i++) {
        hdrs[i] = default_hdrs[i];
    }

    for(int i = 0; i < user_hdr_len; i++) {
        hdrs[i + ARRLEN(default_hdrs)] = user_hdrs[i];
    }

    ESP_LOGI(TAG, "Request headers:");
    print_headers(hdrs, ARRLEN(hdrs));

    /* submit request */

    stream_id = nghttp2_submit_request(session_data->h2_session, NULL, hdrs,
            ARRLEN(hdrs), data_prd, stream_user_data);

    if (stream_id < 0) {
        ESP_LOGE(TAG, "Could not submit HTTP request: %s", nghttp2_strerror(stream_id));
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "created new stream: %d", stream_id);

    session_data->num_outgoing_streams++;

    return stream_id;
}


esp_err_t alloc_ssl_session_data(ssl_session_data_t **session_ptr)
{
    *session_ptr = mbedtls_calloc(1, sizeof(ssl_session_data_t) );
    if(*session_ptr == NULL)
        return ESP_ERR_NO_MEM;

    // TODO: doesn't work
    // struct ssl_session_data *session = *session_ptr;

    (*session_ptr)->ssl_context = mbedtls_calloc(1, sizeof(mbedtls_ssl_context) );
    if((*session_ptr)->ssl_context == NULL)
        return ESP_ERR_NO_MEM;

    (*session_ptr)->server_fd = mbedtls_calloc(1, sizeof(mbedtls_net_context) );
    if((*session_ptr)->server_fd == NULL)
        return ESP_ERR_NO_MEM;

    (*session_ptr)->entropy = mbedtls_calloc(1, sizeof(mbedtls_entropy_context) );
    if((*session_ptr)->entropy == NULL)
        return ESP_ERR_NO_MEM;

    (*session_ptr)->ctr_drbg = mbedtls_calloc(1, sizeof(mbedtls_ctr_drbg_context) );
    if((*session_ptr)->ctr_drbg == NULL)
        return ESP_ERR_NO_MEM;

    return ESP_OK;
}


/*
 * Make an encrypted TLS connection.
 */
int32_t open_ssl_connection(ssl_session_data_t **ssl_session_ptr, char *host, uint16_t port)
{
    int32_t ret;

    if((ret = alloc_ssl_session_data(ssl_session_ptr)) != ESP_OK)
    {
        ESP_LOGE(TAG, "failed to allocate ssl_session: %d", ret);
        return ret;
    }

    ssl_session_data_t *ssl_session = (*ssl_session_ptr);
    mbedtls_entropy_context *entropy = ssl_session->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = ssl_session->ctr_drbg;
    mbedtls_ssl_context *ssl_context = ssl_session->ssl_context;

    mbedtls_x509_crt cacert;

    mbedtls_ssl_config *conf = mbedtls_calloc(1, sizeof(mbedtls_ssl_config));
    ssl_session->conf = conf;

    mbedtls_net_context *server_fd = ssl_session->server_fd;

    // configure ALPN
    const char *alpn_list[3];
    memset( (void * ) alpn_list, 0, sizeof( alpn_list ) );
    alpn_list[0] = "h2";
    alpn_list[1] = "http/1.1";
    alpn_list[2] = NULL;


    mbedtls_ssl_init(ssl_context);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(conf);

    mbedtls_entropy_init(entropy);
    ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, NULL, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        return ret;
    }

    // alpn
    if((ret = mbedtls_ssl_conf_alpn_protocols(conf, alpn_list )) != 0 )
     {
         ESP_LOGI(TAG, " failed\n  ! mbedtls_ssl_conf_alpn_protocols returned %d", ret );
         return ret;
     }

    /* restrict cypher suites */
    int cypher[3];
    memset((void *) cypher, 0, sizeof(cypher));
    cypher[0] = MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    cypher[1] = MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
    cypher[2] = (int) NULL;
    mbedtls_ssl_conf_ciphersuites(conf, cypher);

    /*
     ESP_LOGI(TAG, "Loading the CA root certificate...");

     ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
     server_root_cert_pem_end-server_root_cert_pem_start);

    if (ret < 0) {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x", -ret);
        return ESP_FAIL;
    }
    */

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    /* Hostname set here should match CN in server certificate */
    if ((ret = mbedtls_ssl_set_hostname(ssl_context, host)) != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        return ret;
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        return ret;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
     a warning if CA verification fails but it will continue to connect.

     You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
     */
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);
#ifdef MBEDTLS_DEBUG_C
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
    mbedtls_ssl_conf_dbg(conf, mbedtls_debug, NULL);
#endif

    ret = mbedtls_ssl_setup(ssl_context, conf);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
        return ret;
    }

    /* wifi must be up from this point on */

    mbedtls_net_init(server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%" PRIu16 "...", host, port);

    // convert port to string
    char port_str[6];
    itoa(port, (char*) &port_str, 10);

    ret = mbedtls_net_connect(server_fd, host, port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        return ret;
    }

    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(ssl_context, server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
    //mbedtls_net_set_nonblock(server_fd);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(ssl_context)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            return ret;
        }
    }

    /* ALPN negotiated protocol */
    const char *alp = mbedtls_ssl_get_alpn_protocol( ssl_context );
    ESP_LOGI(TAG, "Application Layer Protocol is %s", alp ? alp : "(none)" );


    /* verify certificate */

    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    uint32_t flags = mbedtls_ssl_get_verify_result(ssl_context);
    if (flags != 0)
    {
        /* In real life, we probably want to close connection if ret != 0 */
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        char *buf = calloc(101, sizeof(char));
        mbedtls_x509_crt_verify_info((char *) buf, 100, "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
        free(buf);
    }
    else
    {
        ESP_LOGI(TAG, "Certificate verified.");
    }

    // configure non-blocking reads
    mbedtls_ssl_conf_read_timeout(conf, 10);

    return 0;
}

/* establish SSL connection and create a new session */
esp_err_t nghttp_new_connection(http2_session_data_t *http2_session, url_t *url)
{
    int32_t ret;
    ssl_session_data_t *ssl_session;

    /* connect using tls */
    ret = open_ssl_connection(&ssl_session, url->host, url->port);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "TLS connection failed");
        free_ssl_session_data(ssl_session, ret);
        return ret;
    }
    http2_session->ssl_session = ssl_session;

    /* transport layer ready */
    return 0;
}


/*
 * Read from the connection
 */
int read_write_loop(http2_session_data_t* http2_session)
{
    nghttp2_session *h2 = http2_session->h2_session;
    mbedtls_ssl_context *ssl_context = http2_session->ssl_session->ssl_context;

    esp_err_t ret = 0;
    uint8_t buf[1024];
    bzero(buf, sizeof(buf));

    // Alexa will close the connection after 5 minutes of inactivity
    time_t last_action;
    time(&last_action);

    do {

        if(difftime(time(NULL), last_action) > 4 * 60) {
            nghttp2_submit_ping(h2, NGHTTP2_FLAG_NONE, NULL);
            time(&last_action);
        }

        if(!nghttp2_session_want_write(h2) && !nghttp2_session_want_read(h2)) {
            // ESP_LOGE(TAG, "!nghttp2_session_want_write(session) && !nghttp2_session_want_read(session)");
            break;
        }

        /* send pending outgoing frames */
        if(nghttp2_session_want_write(h2)) {
            ret = nghttp2_session_send(h2);
            // ESP_LOGI(TAG, "nghttp2_session_send ret = %d", ret);
            if (ret != 0) {
                ESP_LOGE(TAG, "Fatal error: %s", nghttp2_strerror(ret));
                break;
            }

            time(&last_action);
        }

        // avoid blocking read
        if(!nghttp2_session_want_read(h2)) {
            // ESP_LOGI(TAG, "!nghttp2_session_want_read()");
            continue;
        }


        ret = mbedtls_ssl_read(ssl_context, buf, sizeof(buf) );
        // ESP_LOGI(TAG, "mbedtls_ssl_read ret = %d", ret);

        if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            // ESP_LOGI(TAG, "%u MBEDTLS_ERR_SSL_WANT_READ || MBEDTLS_ERR_SSL_WANT_WRITE", __LINE__);
            continue;
        }

        if(ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            // ESP_LOGI(TAG, "mbedtls_ssl_read ret = MBEDTLS_ERR_SSL_TIMEOUT");
            continue;
        }

        if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            ESP_LOGI(TAG, "The peer notified us that the connection is going to be closed.");
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


        // ESP_LOGI(TAG, "%d bytes read", ret);

        // copy received bytes to nghttp2
        ret = nghttp2_session_mem_recv(h2,
                buf, ret);

        if (ret < 0) {
            ESP_LOGW(TAG, "Fatal error: %s", nghttp2_strerror((int ) ret));
            break;
        }

        time(&last_action);

    } while (ret >= 0 || ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||  MBEDTLS_ERR_SSL_TIMEOUT);

    ESP_LOGW(TAG, "read_write_loop finished");

    return ret;
}

/* task to read/write to the network */
void event_loop_task(void *pvParameters)
{
    ESP_LOGI(TAG, "starting network loop");
    http2_session_data_t* http2_session = pvParameters;
    int ret = read_write_loop(http2_session);
    ESP_LOGI(TAG, "event loop finished with %d", ret);

    free_http2_session_data(http2_session, ret);

    ESP_LOGI(TAG, "event_loop_task stack: %d", uxTaskGetStackHighWaterMark(NULL));

    vTaskDelete(NULL);
}


/* Make a new request. */
int nghttp_new_session(http2_session_data_t **http2_session_ptr,
					char *uri, char *method,
					int32_t *stream_id,
        			nghttp2_nv *headers, size_t hdr_len,
			        nghttp2_data_provider *data_provider_struct,
			        nghttp2_session_callbacks *callbacks,
			        void *stream_user_data,
			        void *session_user_data)
{
    int ret;
    http2_session_data_t *session_data;
    url_t *url;

    ESP_LOGI(TAG, "new nghttp session, uri: %s", uri);

    /* allocate http2 session */
    if((ret = alloc_http2_session_data(http2_session_ptr)) != 0) {
        return ret;
    }
    session_data = (*http2_session_ptr);
    session_data->user_data = session_user_data;

    /* parse url */
    if((url = url_parse(uri)) == NULL) {
        return -1;
    }

    /* make ssl connection */
    if(false) {
        if((ret = nghttp_new_connection(session_data, url) != 0)) {
            url_free(url);
            return ret;
        }
    }

    // register callbacks
    if((ret = register_session_callbacks(&session_data->h2_session, callbacks, session_data)) != 0) {
        url_free(url);
        return ret;
    }

    // send request
    ESP_LOGI(TAG, "Writing HTTP request...");

    // send client settings
    send_client_connection_header(session_data->h2_session);
    if(((*stream_id) = submit_request(session_data, url, headers, hdr_len, method, data_provider_struct, stream_user_data)) < 0) {
    	ESP_LOGI(TAG, "failed to submit request");
    	url_free(url);
        return (*stream_id);
    }

    url_free(url);
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    return ret;
}


int32_t nghttp_new_stream(http2_session_data_t *http2_session,
        int32_t *stream_id,
        void *stream_user_data,
        char *uri, char *method,
        nghttp2_nv *headers,  size_t hdr_len,
        nghttp2_data_provider *data_provider_struct)
{
    url_t *url;

    ESP_LOGI(TAG, "new nghttp stream, uri: %s", uri);

    /* parse url */
    if((url = url_parse(uri)) == NULL) {
        ESP_LOGI(TAG, "failed to create url %s", uri);
        return -1;
    }

    if(((*stream_id) = submit_request(http2_session, url, headers, hdr_len, method, data_provider_struct, stream_user_data)) < 0) {
        ESP_LOGI(TAG, "failed to submit request");
        url_free(url);
        return (*stream_id);
    }

    url_free(url);

    return 0;
}

