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
#include "nghttp2/nghttp2.h"
#include "nghttp2_client.h"
#include "asio.h"
#include "asio_http2.h"

#define TAG "asio_test"


void asio_test_http2()
{
    char *user_data = "";
    asio_registry_t *registry;
    asio_registry_init(&registry, user_data);

    char *uri = "https://www.google.de/";
    uri = "https://http2.golang.org/";
    char *method = "GET";

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);

    int32_t stream_id;
    http2_session_data_t *http2_session_ptr;

    int res = asio_new_http2_session(
                registry,
                &http2_session_ptr,
                uri, method,
                &stream_id,
                NULL, 0,
                NULL,
                callbacks,
                NULL,
                NULL);

    if(res != 0)
        return;


    while(1) {
        if(asio_registry_poll(registry) < 1)
            break;
    }

    asio_registry_destroy(registry);
}
