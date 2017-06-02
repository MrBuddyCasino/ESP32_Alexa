/*
 * asio_test.c
 *
 *  Created on: 24.05.2017
 *      Author: michaelboeckling
 */

#include <stdlib.h>
#include <stdio.h>

#include "esp_log.h"
#include "common_buffer.h"
#include "url_parser.h"
#include "http_parser.h"
#include "asio.h"
#include "include/asio_http.h"

#define TAG "asio_test"

int http(http_parser* parser)
{
    return 0;
}

int cb_on_message_complete(http_parser* parser)
{
    printf("cb_on_message_complete\n");

    asio_connection_t *conn = parser->data;
    if(http_should_keep_alive(parser)) {
        ESP_LOGE(TAG, "http_should_keep_alive");
        conn->user_flags |= TASK_FLAG_TERMINATE;
    } else {
        conn->user_flags |= TASK_FLAG_TERMINATE;
        ESP_LOGE(TAG, "! http_should_keep_alive");
    }

    return 0;
}

int http_data(http_parser* parser, const char *at, size_t length)
{
    printf("%.*s\n", length, at);
    return 0;
}

asio_result_t asio_event_handler(struct asio_connection_t *conn)
{
    // printf("asio cb event: %d\n", event);
    return ASIO_OK;
}

void asio_test_http()
{
    char *user_data = "";
    asio_registry_t *registry;
    asio_registry_init(&registry, user_data);

    char *uri = "http://boeckling.net/";
    uri = "https://www.heise.de/newsticker/";
    char *method = "GET";
    http_header_t headers[0];
    uint16_t header_len = 0;

    http_parser_settings *callbacks = calloc(1, sizeof(http_parser_settings));
    callbacks->on_body = http_data;
    callbacks->on_chunk_complete = http;
    callbacks->on_chunk_header = http;
    callbacks->on_header_field = http_data;
    callbacks->on_header_value = http_data;
    callbacks->on_headers_complete = http;
    callbacks->on_message_begin = http;
    callbacks->on_message_complete = cb_on_message_complete;
    callbacks->on_status = http_data;
    callbacks->on_url = http_data;

    asio_event_handler_t cb = asio_event_handler;

    int ret = asio_new_http_request(registry, uri, method, headers, header_len, callbacks, cb, user_data);

    while(1) {
        if(asio_registry_poll(registry) < 1)
            break;
    }

    free(callbacks);
    asio_registry_destroy(registry);
}
