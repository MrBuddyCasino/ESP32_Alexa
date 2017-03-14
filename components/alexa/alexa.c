/*
 * alexa.c
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "nghttp2/nghttp2.h"
#include "cJSON.h"
#include "esp_log.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"

#include "audio_player.h"


typedef enum
{
    META_HEADERS, META_JSON, AUDIO_HEADERS, AUDIO_DATA, DONE
} part_type_t;

typedef struct
{
    part_type_t next_action;
    uint8_t *file_pos;
} alexa_request_t;

typedef struct
{
    multipart_parser* m_parser;
    part_type_t current_part;
    player_t *player_config;
} alexa_response_t;

typedef struct
{
    alexa_request_t *request;
    alexa_response_t *response;
} alexa_session_t;


/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives =
        "https://avs-alexa-eu.amazon.com/v20160207/directives";
static char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";
// static char *uri_events = "https://192.168.101.20:8443/test-server/";

#define TAG "alexa"

#define NL "\r\n"
#define TOKEN "Bearer Atza|IwEBIClICkTSelocZSPV7nzLvaZrllTBwZn1dBGYeiB83UaVNgyvAiQ5Eu6EZZs4DCS-X0glQ6Q2o5Dx1Zo5Tl-zvrYxm3Y1r_zIpDzve80lN13QS2QwDRJJT2tCUkv5RnXUAYBsLyYIBILpvCfPvZw8FY0gKy8xYCZc_vOoKWxlFr1fnuXVEqtUCveXkdo0DqlqdE7Nl6pAIVnDzMGq3XavB16wtecD9Vf-jLL5rQTPJR4eRgUyBPuajR7FAqaj9BQprGtlGBo-ZAGyJrecG10rMyEWJrhcD23n3gmE3Bh3T5H6-us4dtKzvOCAsCioMm9_ExSpM7tdWt8-AmZLG2QZP_nbAmfQkH0tjM_vWaMpESyJ-1ABP0d30lxwWEZ2tXRVy_bW1-GV-sk6QLfMr9IgAySFyoMIVB8raf6Ke4SwvXjCUqDpUzza-Cuyx2saT-dy6IrKHzITKHpv9ekxVXvF3NQg4KMe-YZSm9zLDK1rGPFygzCjhLmNcmPFYLihIuMI234CIGJ8T_2dnn7RMqjFCOZEsqOAs8xIHF0-6o_LXfZY3g"
#define BOUNDARY_TERM "nghttp2123456789"
#define BOUNDARY_LINE NL "--" BOUNDARY_TERM NL
#define BOUNDARY_EOF NL "--" BOUNDARY_TERM "--" NL
#define HDR_FORM_DATA "multipart/form-data; boundary=\"" BOUNDARY_TERM "\""

#define HDR_DISP_META "Content-Disposition: form-data; name=\"metadata\"" NL
#define HDR_TYPE_JSON "Content-Type: application/json; charset=UTF-8" NL
#define JSON_PART_PREFIX BOUNDARY_LINE HDR_DISP_META HDR_TYPE_JSON NL

#define HDR_DISP_AUDIO "Content-Disposition: form-data; name=\"audio\"" NL
#define HDR_TYPE_OCTET "Content-Type: application/octet-stream" NL
#define AUDIO_PART_PREFIX BOUNDARY_LINE HDR_DISP_AUDIO HDR_TYPE_OCTET NL

/* embedded file */
extern const uint8_t file_start[] asm("_binary_what_time_raw_start");
extern const uint8_t file_end[] asm("_binary_what_time_raw_end");

static char* create_json_metadata()
{
    cJSON *root, *event, *header, *payload;
    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "context", cJSON_CreateArray());
    cJSON_AddItemToObject(root, "event", event = cJSON_CreateObject());

    cJSON_AddItemToObject(event, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "SpeechRecognizer");
    cJSON_AddStringToObject(header, "name", "Recognize");
    cJSON_AddStringToObject(header, "messageId", "msg123");
    cJSON_AddStringToObject(header, "dialogRequestId", "req345");

    cJSON_AddItemToObject(event, "payload", payload = cJSON_CreateObject());
    cJSON_AddStringToObject(payload, "profile", "CLOSE_TALK");
    cJSON_AddStringToObject(payload, "format",
            "AUDIO_L16_RATE_16000_CHANNELS_1");

    char *rendered = cJSON_Print(root);

    cJSON_Delete(root);

    return rendered;
}

static bool did_yield = false;


/* multipart callbacks */
int on_header_field(multipart_parser *parser, const char *at, size_t length) {
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);

    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}
int on_header_value(multipart_parser *parser, const char *at, size_t length) {
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);

    // assumes audio on application/octet-stream
    if(strncmp("application/octet-stream", at, length) == 0) {
        printf("audio part detected\n");
        alexa_response->current_part = AUDIO_DATA;

        printf("starting player\n");
        audio_player_init(alexa_response->player_config);
        audio_player_start(alexa_response->player_config);
    }

    printf("on_header_value %.*s\n", (int)length, at);

    return 0;
}
int on_part_data(multipart_parser *parser, const char *at, size_t length) {
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);

    if(alexa_response->current_part == AUDIO_DATA)
    {
        // printf("feeding player\n");
        audio_stream_consumer(at, length, alexa_response->player_config);
    }

    // printf("%.*s: ", length, at);
    return 0;
}

/** called before header name/value :-/ */
int on_part_data_begin(multipart_parser *parser)
{
    printf("on_part_data_begin\n");
    return 0;
}

int on_headers_complete(multipart_parser *parser)   { printf("on_headers_complete\n"); return 0; }
int on_part_data_end(multipart_parser *parser)
{
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);
    printf("on_part_data_end\n");

    if(alexa_response->current_part == AUDIO_DATA) {
        printf("stopping player\n");
        // audio_player_stop(alexa_response->player_config);
    }

    return 0;
}
int on_body_end(multipart_parser *parser)           { printf("on_body_end\n"); return 0; }

void init_multipart_parser(alexa_response_t *alexa_response, char *boundary_term)
{
    ESP_LOGI(TAG, "init multipart_parser: %s", boundary_term);

    multipart_parser_settings *callbacks = calloc(1, sizeof(multipart_parser_settings));

    callbacks->on_header_field = on_header_field;
    callbacks->on_header_value = on_header_value;
    callbacks->on_headers_complete = on_headers_complete;
    callbacks->on_part_data = on_part_data;
    callbacks->on_part_data_begin = on_part_data_begin;
    callbacks->on_part_data_end = on_part_data_end;
    callbacks->on_body_end = on_body_end;

    multipart_parser* m_parser = multipart_parser_init(boundary_term, callbacks);
    multipart_parser_set_data(m_parser, alexa_response);
    alexa_response->m_parser = m_parser;
    alexa_response->current_part = META_HEADERS;
}


/* send data  */
ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    alexa_request_t *alexa_session = data_source->ptr;

    ssize_t bytes_written = 0;
    part_type_t next_action = alexa_session->next_action;

    if(!did_yield) {
        did_yield = true;
        // return NGHTTP2_ERR_DEFERRED;
    }

    switch (next_action) {
        case META_HEADERS:
        case META_JSON:
            ; // fix C grammar oddity
            // write multipart headers
            size_t prefix_len = strlen(JSON_PART_PREFIX);
            memcpy(buf, JSON_PART_PREFIX, prefix_len);

            // write json
            char *json = create_json_metadata();
            size_t json_len = strlen(json);
            memcpy(buf + prefix_len, json, json_len);
            free(json);
            bytes_written = prefix_len + json_len;

            alexa_session->next_action = AUDIO_HEADERS;
            break;

        case AUDIO_HEADERS:
            bytes_written = strlen(AUDIO_PART_PREFIX);
            memcpy(buf, AUDIO_PART_PREFIX, bytes_written);
            alexa_session->next_action = AUDIO_DATA;
            break;

        case AUDIO_DATA:

            if(alexa_session->file_pos == 0)
                alexa_session->file_pos = file_start;

            uint8_t *pos = alexa_session->file_pos;
            // size_t file_size = file_end - file_start;
            size_t remaining = file_end - pos;
            bytes_written = buf_length < remaining ? buf_length : remaining;
            memcpy(buf, pos, bytes_written);

            if(buf_length > remaining) {
                alexa_session->next_action = DONE;
            }

            alexa_session->file_pos += bytes_written;

            break;

        case DONE:
            bytes_written = strlen(BOUNDARY_EOF);
            memcpy(buf, BOUNDARY_EOF, bytes_written);
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            break;
    }

    // printf("writing %d bytes to stream_id: %d, buf length: %d\n", bytes_written, stream_id, buf_length);
    printf("%d bytes out\n", bytes_written);

    return bytes_written;
}

/* receive header */
int header_callback(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen,
                      uint8_t flags, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    alexa_session_t *alexa_session = session_data->user_data;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            /* Print response headers for the initiated request. */
            printf("%s: %s\n", name, value);

            // parse boundary term
            if(strcmp("content-type", (char*)name) == 0) {
                char* start = strstr((char*)value, "boundary=");
                if(start != NULL) {
                    start += strlen("boundary=");
                    char* end = strstr(start, ";");
                    if(end != NULL) {
                        // make room for '--' prefix
                        start -= 2;
                        char* boundary_term = strndup(start, end - start);
                        boundary_term[0] = '-';
                        boundary_term[1] = '-';
                        init_multipart_parser(alexa_session->response, boundary_term);
                    }
                }
            }
        }
        break;
    }

    return 0;
}


/* receive data */
int recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    alexa_session_t *alexa_session = session_data->user_data;

    // will be non-null after boundary term was detected
    if(alexa_session->response->m_parser != NULL) {
        multipart_parser_execute(alexa_session->response->m_parser, (char*)data, len);
    }

    // printf("%.*s", len, data);
    return 0;
}


int stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);

    session_data->num_outgoing_streams--;
    if (session_data->num_outgoing_streams == 0) {
        ESP_LOGE(TAG, "no more open streams, terminating session");
        if (nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    return 0;
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

void alexa_init()
{

    http2_session_data *http2_session;

    alexa_session_t *alexa_session = calloc(1, sizeof(alexa_session));
    alexa_session->request = calloc(1, sizeof(alexa_request_t));
    alexa_session->request->next_action = META_HEADERS;
    alexa_session->response = calloc(1, sizeof(alexa_response_t));

    // init player
    player_t *player_config = calloc(1, sizeof(player_t));
    alexa_session->response->player_config = player_config;
    player_config->state = STOPPED;

    // init renderer
    player_config->renderer_config = calloc(1, sizeof(renderer_config_t));
    renderer_config_t *renderer_config = player_config->renderer_config;
    renderer_config->bit_depth = I2S_BITS_PER_SAMPLE_16BIT;
    renderer_config->i2s_num = I2S_NUM_0;
    renderer_config->sample_rate = 44100;
    renderer_config->output_mode = I2S;


    nghttp2_data_provider *data_provider_struct = calloc(1,
            sizeof(nghttp2_data_provider));
    data_provider_struct->read_callback = data_source_read_callback;
    data_provider_struct->source.ptr = alexa_session->request;

    // add headers
    nghttp2_nv hdrs[2] = {
            MAKE_NV2("authorization", TOKEN),
            MAKE_NV2("content-type", HDR_FORM_DATA)
    };

    esp_err_t ret = nghttp_new_request(&http2_session,
            alexa_session,
            uri_events, "POST",
            hdrs, 2,
            data_provider_struct,
            header_callback,
            recv_callback,
            stream_close_callback);

    // struct has now been copied by nghttp2
    free(data_provider_struct);

    return;
}
