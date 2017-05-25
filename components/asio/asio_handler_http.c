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
#include "common_buffer.h"
#include "url_parser.h"
#include "http_parser.h"
#include "asio.h"
#include "asio_proto.h"

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
    http_proto_ctx_t *proto_ctx = conn->proto_context;

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


    http_proto_ctx_t *http_ctx = conn->proto_context;
    http_ctx->parser = calloc(1, sizeof(http_parser));
    if(http_ctx->parser == NULL)
        return ASIO_CB_ERR;

    http_parser_init(http_ctx->parser, HTTP_RESPONSE);
    http_ctx->parser->data = conn;

    return ASIO_CB_OK;
}

asio_cb_res_t asio_http_handle_close(asio_connection_t *conn, void *user_data)
{
    // ESP_LOGI(TAG, "destroying http_proto_ctx_t");
    if(conn->proto_context != NULL) {
        http_proto_ctx_t *proto_ctx = conn->proto_context;
        free(proto_ctx->callbacks);
        free(proto_ctx->headers);
        free(proto_ctx->parser);
        free(proto_ctx);
    }

    return ASIO_CB_OK;
}

asio_cb_res_t asio_http_handle_data_recv(asio_connection_t *conn, void *user_data)
{
    http_proto_ctx_t *proto_ctx = conn->proto_context;

    int nparsed = http_parser_execute(proto_ctx->parser, proto_ctx->callbacks,
            (char*)conn->recv_buf->read_pos, buf_data_unread(conn->recv_buf));

    if(nparsed >= 0)
    {
        conn->recv_buf->read_pos += nparsed;
        return ASIO_CB_OK;
    } else
    {
        return ASIO_CB_ERR;
    }
}

asio_cb_res_t asio_proto_handler_http(asio_connection_t *conn, asio_event_t event, void *user_data)
{
    switch (event) {
        case ASIO_EVT_CONNECTED:
            asio_http_handle_connect(conn, user_data);
            break;

        case ASIO_EVT_CLOSE:
            asio_http_handle_close(conn, user_data);
            break;

        case ASIO_EVT_DATA_RECV:
            return asio_http_handle_data_recv(conn, user_data);
            break;
    }

    return ASIO_CB_OK;
}


int asio_http_request(asio_registry_t *registry, char *uri, char *method, http_header_t headers[], uint16_t header_len, http_parser_settings *callbacks, asio_event_handler_t cb, void *user_data)
{
    url_t *url = url_parse(uri);
    if(!url) return -1;

    asio_connection_t *conn = calloc(1, sizeof(asio_connection_t));
    conn->registry = registry;
    conn->url = url;
    conn->evt_handler = cb;
    conn->user_data = user_data;
    conn->transport = ASIO_TCP;
    conn->fd = -1;
    conn->proto_handler = asio_proto_handler_http;
    conn->state = ASIO_CONN_NEW;

    http_proto_ctx_t *proto_ctx = calloc(1, sizeof(http_proto_ctx_t));
    conn->proto_context = proto_ctx;
    proto_ctx->callbacks = callbacks;
    proto_ctx->headers = headers;
    proto_ctx->header_len = header_len;
    proto_ctx->method = method;

    if(strstr(url->scheme, "https"))
    {
        conn->transport = ASIO_TCP_SSL;
    }
    else if(strstr(url->scheme, "http"))
    {
        conn->transport = ASIO_TCP;
    } else
    {
        ESP_LOGE(TAG, "unsupported scheme: %s", url->scheme);
        asio_registry_remove_connection(conn);
        return -1;
    }

    conn->send_buf = buf_create(512);
    conn->recv_buf = buf_create(512);

    if(asio_registry_add_connection(registry, conn) < 0) {
        ESP_LOGE(TAG, "failed to add connection");
        asio_registry_remove_connection(conn);
        return -1;
    }

    return 0;
}
