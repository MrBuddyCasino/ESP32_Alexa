/*
 * downstream_handler.c
 *
 *  Created on: 21.04.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "esp_log.h"
#include "multipart_parser.h"
#include "cJSON.h"
#include "nghttp2/nghttp2.h"
#include "nghttp2_client.h"

#include "audio_player.h"
#include "alexa.h"
#include "alexa_directive_handler.h"
#include "web_radio.h"
#include "event_send_speech.h"

#define TAG "handler_directives"



/* multipart callbacks */
static int on_multipart_header_field(multipart_parser *parser, const char *at, size_t length)
{
    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}

static int on_multipart_header_value(multipart_parser *parser, const char *at, size_t length)
{
    printf("on_header_value %.*s\n", (int)length, at);
    return 0;
}

static int on_multipart_data(multipart_parser *parser, const char *at, size_t length)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);

    printf("on_multipart_data:\n%.*s\n", length, at);
    if(strstr(at, "StopCapture"))
    {
        ESP_LOGW(TAG, "StopCapture detected");
        speech_recognizer_stop_capture(alexa_stream->alexa_session);
    }

    return 0;
}

/** called before header name/value :-/ */
static int on_multipart_data_begin(multipart_parser *parser)
{
    printf("on_part_data_begin\n");
    return 0;
}

static int on_multipart_headers_complete(multipart_parser *parser)
{
    printf("on_headers_complete\n"); return 0;
}

static int on_multipart_data_end(multipart_parser *parser)
{
    printf("on_part_data_end\n");
    return 0;
}

static int on_multipart_body_end(multipart_parser *parser)
{
    printf("on_body_end\n");
    return 0;
}

void stream_handler_directives_init_multipart_parser(alexa_stream_t *alexa_stream, char *boundary_term)
{
    ESP_LOGI(TAG, "init multipart_parser: %s", boundary_term);

    multipart_parser_settings *callbacks = calloc(1, sizeof(multipart_parser_settings));

    callbacks->on_header_field = on_multipart_header_field;
    callbacks->on_header_value = on_multipart_header_value;
    callbacks->on_headers_complete = on_multipart_headers_complete;
    callbacks->on_part_data = on_multipart_data;
    callbacks->on_part_data_begin = on_multipart_data_begin;
    callbacks->on_part_data_end = on_multipart_data_end;
    callbacks->on_body_end = on_multipart_body_end;

    multipart_parser* m_parser = multipart_parser_init(boundary_term, callbacks);
    multipart_parser_set_data(m_parser, alexa_stream);
    alexa_stream->m_parser = m_parser;
    alexa_stream->boundary = boundary_term;
}
