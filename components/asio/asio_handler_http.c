/*
 * asio_handler_http.c
 *
 *  Created on: 23.05.2017
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
#include "http_parser.h"
#include "brssl.h"

#include "asio.h"
#include "asio_proto.h"
#include "asio_socket.h"

#define TAG "asio_http"


typedef struct {
    char *method;
    http_header_t *headers;
    uint16_t header_len;
    http_parser *parser;
    http_parser_settings *callbacks;
} http_proto_ctx_t;



/* socket connected, write http request */
asio_cb_res_t asio_http_handle_connect(asio_connection_t *conn, void *user_data)
{
    ESP_LOGW(TAG, "asio_http_handle_connect()");
    http_proto_ctx_t *proto_ctx = conn->proto_ctx;

    // TODO: headers

    int chars_written = snprintf((char*)conn->send_buf->write_pos, buf_free_capacity(conn->send_buf), "%s %s%s%s%s",
            proto_ctx->method, conn->url->path, " HTTP/1.1\r\nHost: ", conn->url->host, "\r\n\r\n");

    if(chars_written >= 0 && chars_written < buf_free_capacity(conn->send_buf)) {
        // OK
        buf_fill(conn->send_buf, chars_written);
        ESP_LOGI(TAG, "%.*s", chars_written, conn->send_buf->read_pos);
    } else {
        ESP_LOGE(TAG, "error writing request: %s", conn->url->host);
    }

    return ASIO_CB_OK;
}

asio_cb_res_t asio_http_handle_close(asio_connection_t *conn, void *user_data)
{
    // ESP_LOGI(TAG, "destroying http_proto_ctx_t");
    if(conn->proto_ctx != NULL) {
        http_proto_ctx_t *proto_ctx = conn->proto_ctx;
        free(proto_ctx->callbacks);
        free(proto_ctx->headers);
        free(proto_ctx->parser);
        free(proto_ctx);
    }

    return ASIO_CB_OK;
}

asio_cb_res_t asio_http_handle_data_recv(asio_connection_t *conn, void *user_data)
{
    http_proto_ctx_t *proto_ctx = conn->proto_ctx;

    // TODO: send?

    if(buf_data_unread(conn->recv_buf) == 0)
        return ASIO_CB_OK;

    // process received
    int nparsed = http_parser_execute(proto_ctx->parser, proto_ctx->callbacks,
            (char*)conn->recv_buf->read_pos, buf_data_unread(conn->recv_buf));

    // ESP_LOGI(TAG, "asio_http_handle_data_recv(), buf_data_unread=%d, nparsed=%d", buf_data_unread(conn->recv_buf), nparsed);

    if(nparsed >= 0)
    {
        buf_drain(conn->recv_buf, nparsed);
        return ASIO_CB_OK;
    } else
    {
        ESP_LOGE(TAG, "http_parser_execute() error: %d", nparsed);
        return ASIO_CB_ERR;
    }
}

asio_cb_res_t asio_proto_handler_http(asio_connection_t *conn, asio_event_t event, void *user_data)
{
    switch (event) {
        case ASIO_EVT_NEW:
            break;

        case ASIO_EVT_CONNECTED:
            asio_http_handle_connect(conn, user_data);
            break;

        case ASIO_EVT_CLOSE:
            asio_http_handle_close(conn, user_data);
            break;

        case ASIO_EVT_SOCKET_READY:
            return asio_http_handle_data_recv(conn, user_data);
            break;
    }

    return ASIO_CB_OK;
}


int asio_new_http_request(asio_registry_t *registry, char *uri, char *method, http_header_t headers[], uint16_t header_len, http_parser_settings *callbacks, asio_event_handler_t cb, void *user_data)
{
    asio_connection_t *conn;

    if(starts_with(uri, "https://"))
    {
        int bidi = 1;
        char *alpn = NULL;
        cipher_suite *suites = NULL;
        size_t num_suites = 0;
        conn = asio_new_ssl_connection(registry, uri, bidi, alpn, suites, num_suites, user_data);
    }
    else if(starts_with(uri, "http://"))
    {
        conn = asio_new_socket_connection(registry, ASIO_TCP, uri, user_data);
    }
    else {
        ESP_LOGE(TAG, "unsupported url scheme: %s", uri);
        return -1;
    }

    conn->evt_handler = cb;
    conn->proto_handler = asio_proto_handler_http;

    http_proto_ctx_t *proto_ctx = calloc(1, sizeof(http_proto_ctx_t));
    conn->proto_ctx = proto_ctx;
    proto_ctx->callbacks = callbacks;
    proto_ctx->headers = headers;
    proto_ctx->header_len = header_len;
    proto_ctx->method = method;

    proto_ctx->parser = calloc(1, sizeof(http_parser));
    if(proto_ctx->parser == NULL)
        return ASIO_CB_ERR;

    http_parser_init(proto_ctx->parser, HTTP_RESPONSE);
    proto_ctx->parser->data = conn;

    return 0;
}
