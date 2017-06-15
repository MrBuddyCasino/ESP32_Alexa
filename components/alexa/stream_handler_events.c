/*
 * eventstream_handler.c
 *
 *  Created on: 21.04.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "cJSON.h"
#include "nghttp2/nghttp2.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"
#include "common_buffer.h"
#include "audio_player.h"
#include "web_radio.h"
#include "ui.h"
#include "alexa.h"
#include "alexa_speech_recognizer.h"

#define TAG "handler_events"



void handle_speak_directive(alexa_session_t *alexa_session, cJSON *directive)
{
    ;
}

static void start_web_radio(char *play_url)
{
    // init web radio
    web_radio_t *radio_config = calloc(1, sizeof(web_radio_t));
    radio_config->url = play_url;

    // init player config
    radio_config->player_config = calloc(1, sizeof(player_t));
    radio_config->player_config->command = CMD_NONE;
    radio_config->player_config->decoder_status = UNINITIALIZED;
    radio_config->player_config->decoder_command = CMD_NONE;
    radio_config->player_config->buffer_pref = BUF_PREF_SAFE;
    radio_config->player_config->media_stream = calloc(1, sizeof(media_stream_t));

    // init renderer
    // renderer_init(create_renderer_config());

    // start radio
    web_radio_init(radio_config);
    web_radio_start(radio_config);
}

void handle_play_directive(alexa_session_t *alexa_session, cJSON *directive)
{
    cJSON *payload = cJSON_GetObjectItem(directive, "payload");
    cJSON *audioItem = cJSON_GetObjectItem(payload, "audioItem");
    cJSON *stream = cJSON_GetObjectItem(audioItem, "stream");
    cJSON *url = cJSON_GetObjectItem(stream, "url");

    // inline audio
    if(strncmp("cid", url->valuestring, 3) == 0)
    {
        return;
    }

    ESP_LOGI(TAG, "playing url %s", url->valuestring);
    start_web_radio(strdup(url->valuestring));
}

void handle_directive(alexa_session_t *alexa_session, const char *at, size_t length)
{
    printf("handle_directive:\n%.*s\n", length, at);

    // reset speech recognizer to idle
    speech_recognizer_set_state(SPEECH_IDLE);

    cJSON *root = cJSON_Parse(at);

    cJSON *directive = cJSON_GetObjectItem(root, "directive");
    cJSON *header = cJSON_GetObjectItem(directive, "header");
    cJSON *name = cJSON_GetObjectItem(header, "name");

    if(strstr(name->valuestring, "Speak"))
    {
        ui_queue_event(UI_SYNTHESIZING_SPEECH);
        handle_speak_directive(alexa_session, directive);
    }
    else if(strstr(name->valuestring, "Play"))
    {
        handle_play_directive(alexa_session, directive);
    }

    cJSON_Delete(root);
}


/* multipart callbacks */
static int on_multipart_header_field(multipart_parser *parser, const char *at, size_t length)
{
    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}

static int on_multipart_header_value(multipart_parser *parser, const char *at, size_t length)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    printf("on_header_value %.*s\n", (int)length, at);

    // assumes audio on application/octet-stream
    if(strncmp("application/octet-stream", at, length) == 0) {
        printf("audio part detected\n");
        alexa_stream->current_part = AUDIO_DATA;
        player_t *player_config = get_player_config(alexa_session);
        player_config->media_stream->eof = false;
        player_config->media_stream->content_type = AUDIO_MPEG;

        printf("starting player\n");
        audio_player_start(player_config);
    }
    else if (strncmp("application/json; charset=UTF-8", at, length) == 0) {
        printf("directive detected\n");
        alexa_stream->current_part = META_JSON;
    }

    return 0;
}

static buffer_t *json_buf = NULL;
static int on_multipart_data(multipart_parser *parser, const char *at, size_t length)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    if(alexa_stream->current_part == AUDIO_DATA)
    {
        // ESP_LOGI("feeding player\n");
        player_t *player_config = get_player_config(alexa_session);
        audio_stream_consumer(at, length, player_config);
    }
    else if(alexa_stream->current_part == META_JSON)
    {
        //printf("on_multipart_data:\n%.*s\n", length, at);

        if(json_buf == NULL)
            json_buf = buf_create(length);

        int bytes_written = buf_write(json_buf, at, length);
        int bytes_remaining = length - bytes_written;
        if(bytes_remaining > 0) {
            buf_resize(json_buf, json_buf->len + bytes_remaining);
            buf_write(json_buf, at + bytes_written, bytes_remaining);
        }

    }
    else {
        printf("%.*s", length, at);
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
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    printf("on_part_data_end\n");

    if(alexa_stream->current_part == AUDIO_DATA) {
        player_t *player_config = get_player_config(alexa_session);
        player_config->media_stream->eof = true;
        // ensure flush
        audio_stream_consumer(NULL, 0, player_config);
    }

    if(alexa_stream->current_part == META_JSON) {
        handle_directive(alexa_session, (const char *) json_buf->base, json_buf->len);
        buf_destroy(json_buf);
        json_buf = NULL;
    }

    return 0;
}

static int on_multipart_body_end(multipart_parser *parser)
{
    printf("on_body_end\n");
    return 0;
}

void stream_handler_events_init_multipart_parser(alexa_stream_t *alexa_stream, char *boundary_term)
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
    alexa_stream->current_part = META_HEADERS;
}
