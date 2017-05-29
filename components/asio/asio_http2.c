/*
 * asio_http2.c
 *
 *  Created on: 27.05.2017
 *      Author: michaelboeckling
 */

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "common_string.h"
#include "common_buffer.h"
#include "url_parser.h"
#include "brssl.h"
#include "nghttp2/nghttp2.h"
#include "nghttp2_client.h"

#include "asio.h"
#include "asio_socket.h"
#include "include/asio_http.h"

#define TAG "asio_http2"


static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    http2_session_data_t *session_data = user_data;

    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);

    session_data->num_outgoing_streams--;
    if (session_data->num_outgoing_streams < 1) {
        ESP_LOGE(TAG, "no more open streams, terminating session");

        // submit goaway
        nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR,
                NULL, 0);

        // set flag
        asio_connection_t *conn = session_data->conn;
        conn->user_flags |= CONN_FLAG_CLOSE;
    }

    return 0;
}


/* send received bytes to nghttp2 */
static size_t asio_app_recv_cb(asio_connection_t *conn, unsigned char* buf, size_t len)
{
    http2_session_data_t *http2_session = conn->proto_ctx;
    nghttp2_session *h2 = http2_session->h2_session;
    ssize_t ret = 0;

    /* read incoming frames */
    if(nghttp2_session_want_read(h2))
    {
        // feed bytes to nghttp2
        ret = nghttp2_session_mem_recv(h2, buf, len);
        if (ret < 0) {
            ESP_LOGW(TAG, "Fatal error: %s", nghttp2_strerror((int ) ret));
            return ASIO_CB_ERR;
        }
        time(&conn->last_modified);
    }

    // close connection?
    if(!nghttp2_session_want_write(h2) && !nghttp2_session_want_read(h2)) {
        conn->user_flags |= CONN_FLAG_CLOSE;
        ESP_LOGE(TAG, "closing stream");
    }

    return ret;
}

/* read bytes from nghttp2 */
static size_t asio_app_send_cb(asio_connection_t *conn, unsigned char* buf, size_t len)
{
    http2_session_data_t *http2_session = conn->proto_ctx;
    nghttp2_session *h2 = http2_session->h2_session;

    const uint8_t *data = NULL;
    ssize_t sentlen = 0;
    ssize_t datalen = 0;

    //int32_t window_size = nghttp2_session_get_effective_local_window_size(h2);
    //ESP_LOGE(TAG, "effective_local_window_size: %d", window_size);

    // max frame length + http2 header
    size_t min_space = 1024 + 9;

    // enough for max frame size?
    while(len > min_space && nghttp2_session_want_write(h2))
    {
        datalen = nghttp2_session_mem_send(h2, &data);
        if (datalen <= 0) {
            break;
        }

        // shouldn't happen
        if(datalen > len) {
            ESP_LOGE(TAG, "buffer overflow: requested %d, available %d", datalen, len);
            return -1;
        }

        memcpy(buf, data, datalen);
        sentlen += datalen;
        len -= datalen;
        buf += datalen;

        time(&conn->last_modified);
    }

    // close connection?
    if(!nghttp2_session_want_write(h2) && !nghttp2_session_want_read(h2)) {
        conn->user_flags |= CONN_FLAG_CLOSE;
        ESP_LOGE(TAG, "closing stream");
    }

    return sentlen;
}

asio_cb_res_t asio_io_handler_http2(asio_connection_t *conn, asio_event_t event, void *user_data)
{
    http2_session_data_t *http2_session = conn->proto_ctx;

    switch (event) {
        case ASIO_EVT_CLOSE:
            free_http2_session_data(http2_session, 0);
            break;

        default:
            break;
    }

    return ASIO_CB_OK;
}


int asio_new_http2_session(
        asio_registry_t *registry,
        http2_session_data_t **http2_session_ptr,
        char *uri, char *method,
        int32_t *stream_id,
        nghttp2_nv *headers,  size_t hdr_len,
        nghttp2_data_provider *data_provider_struct,
        nghttp2_session_callbacks *callbacks,
        void *stream_user_data,
        void *session_user_data)
{
    asio_connection_t *conn;

    // create socket
    if(starts_with(uri, "https:"))
    {
        int bidi = 1;
        cipher_suite *suites = NULL;
        size_t num_suites = 0;
        conn = asio_new_ssl_connection(registry, ASIO_TCP_SSL, uri, bidi, "h2", suites, num_suites, session_user_data);
    }
    else if(starts_with(uri, "http:"))
    {
        conn = asio_new_socket_connection(registry, ASIO_TCP, uri, session_user_data);
    }
    else {
        ESP_LOGE(TAG, "unsupported url scheme: %s", uri);
        return -1;
    }

    // register data transfer callbacks
    conn->app_recv = asio_app_recv_cb;
    conn->app_send = asio_app_send_cb;

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

    int ret = nghttp_new_session(
                        http2_session_ptr,
                        uri, method,
                        stream_id,
                        headers, hdr_len,
                        data_provider_struct,
                        callbacks,
                        stream_user_data,
                        session_user_data);

    if (ret != 0) {
        ESP_LOGE(TAG, "failed to create nghttp2 session: %d", ret);
        free_http2_session_data(*http2_session_ptr, ret);
        asio_registry_remove_connection(conn);
        return ret;
    }

    conn->proto_ctx = *http2_session_ptr;
    (*http2_session_ptr)->conn = conn;

    conn->proto_handler = asio_io_handler_http2;

    return 0;
}
