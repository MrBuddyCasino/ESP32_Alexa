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
#include "asio_socket.h"
#include "asio_http.h"

#define TAG "asio_http"


typedef struct {
    char *method;
    http_header_t *headers;
    uint16_t header_len;
    http_parser *parser;
    http_parser_settings *callbacks;
} http_proto_ctx_t;



/* socket connected, write http request */
size_t asio_http_write_request(asio_connection_t *conn, unsigned char* buf, size_t len)
{
    http_proto_ctx_t *proto_ctx = conn->proto_ctx;

    // TODO: headers

    int wlen = snprintf((char*)buf, len, "%s %s%s%s%s",
            proto_ctx->method, conn->url->path, " HTTP/1.1\r\nHost: ", conn->url->host, "\r\n\r\n");

    if(wlen >= 0 && wlen < len) {
        // OK
        ESP_LOGI(TAG, "%.*s", wlen, buf);
    } else {
        ESP_LOGE(TAG, "error writing request: %s", conn->url->host);
    }

    return wlen;
}

asio_result_t asio_http_handle_close(asio_connection_t *conn)
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


/* send received bytes to http parser */
static size_t asio_app_recv_cb(asio_connection_t *conn, unsigned char* buf, size_t len)
{
    http_proto_ctx_t *proto_ctx = conn->proto_ctx;

    // process received
    int nparsed = http_parser_execute(proto_ctx->parser, proto_ctx->callbacks,
            (const char*)buf, len);

    if(nparsed < 0)
    {
        ESP_LOGE(TAG, "http_parser_execute() error: %d", nparsed);
        conn->user_flags |= CONN_FLAG_CLOSE;
        return ASIO_CB_ERR;
    }

    return nparsed;
}

typedef enum {
    HTTP_IDLE, HTTP_HEADERS_SENT
} http_state_t;

static http_state_t http_status = HTTP_IDLE;

/* read bytes from app */
static size_t asio_app_send_cb(asio_connection_t *conn, unsigned char* buf, size_t len)
{
    size_t wlen = 0;
    switch(http_status)
    {
        case HTTP_IDLE:
            wlen = asio_http_write_request(conn, buf, len);
            http_status = HTTP_HEADERS_SENT;
            break;

        case HTTP_HEADERS_SENT:
            // TODO
            break;
    }

    return wlen;
}

asio_result_t asio_proto_handler_http(asio_connection_t *conn)
{
    switch (conn->state) {
        case ASIO_CONN_NEW:
            http_status = HTTP_IDLE;
            break;

        case ASIO_CONN_CLOSING:
            asio_http_handle_close(conn);
            break;

        default:
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
        conn = asio_new_ssl_connection(registry, ASIO_TCP_SSL, uri, bidi, alpn, suites, num_suites, user_data);
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
    conn->app_recv = asio_app_recv_cb;
    conn->app_send = asio_app_send_cb;

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
