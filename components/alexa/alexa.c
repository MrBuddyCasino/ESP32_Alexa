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


typedef enum
{
    META_HEADERS, META_JSON, AUDIO_HEADERS, AUDIO_DATA, DONE
} PART_TYPE;

typedef struct
{
    PART_TYPE next_action;
    uint8_t *file_pos;
} alexa_request;

typedef struct
{
    multipart_parser* m_parser;
    PART_TYPE current_part;
} alexa_response;

typedef struct
{
    alexa_request *request;
    alexa_response *response;
} alexa_session;


/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives =
        "https://avs-alexa-eu.amazon.com/v20160207/directives";
static char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";
// static char *uri_events = "https://192.168.101.20:8443/test-server/";

#define TAG "alexa"

#define NL "\r\n"
#define TOKEN "Bearer Atza|IwEBIFwaogzxzd-OQz1QWpBxW0DsYD8efwkioGImLBSX4dDGd6UDvnkLoxBOyrxBB5oKEf0LiCYhz_idr1Y8prKXvd1YCrJ6iEwkwyA5lU1UJiXQa12KAF6pwwCTS77YbNF2qk84i0BcIk3zFegAxLO1KQ96vDgOa0Z296HDvtHGoo5c2JzOtNI79rJRXK0JrFigszoUzyR6NekhzkwcrLtcQmkE3LvWpEkOeRjgRr4OVu4sUqZr-K0p9vtfAIFaX5_iy-YaOkiixCBWYleUfM_5SM_7ilrQ9nHSFW2DcYfyZ7UrJPFEr_0kSTe1J9UvGXSBZlAmYfQ_HrCcsZlyY7GFJ8grdFSAafI4Hkhek8AIFCwLjbXKsSQUDFy8_hax28-6_rs2S3QhZrHpGUM87-Xd0f7gLLUKAtvxM7aINRpUSvkO8INbwQD9XtVtzXDHRdlJnUUUaL0jHDq2TtVdzer7y1L8ov1-fsFlAQu-l-fABG0BLFLxP4uX7kxtDU9a_HAy_Iph0sfcklYMyZ4709OAct2di-ilTmo5o4dNghAJZ69efQ"
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
    alexa_response *alexa_response = multipart_parser_get_data(parser);

    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}
int on_header_value(multipart_parser *parser, const char *at, size_t length) {
    alexa_response *alexa_response = multipart_parser_get_data(parser);

    printf("on_header_value %.*s\n", (int)length, at);
    // assumes audio on application/octet-stream
    return 0;
}
int on_part_data(multipart_parser *parser, const char *at, size_t length) {
    alexa_response *alexa_response = multipart_parser_get_data(parser);

    // printf("%.*s: ", length, at);
    return 0;
}

int on_part_data_begin(multipart_parser *parser)
{
    alexa_response *alexa_response = multipart_parser_get_data(parser);
    printf("on_part_data_begin\n");

    // start MP3 decoder
    if(alexa_response->current_part == AUDIO_DATA)
    {
        ;
    }

    return 0;
}

int on_headers_complete(multipart_parser *parser)   { printf("on_headers_complete\n"); return 0; }
int on_part_data_end(multipart_parser *parser)      { printf("on_part_data_end\n"); return 0; }
int on_body_end(multipart_parser *parser)           { printf("on_body_end\n"); return 0; }

void init_multipart_parser(alexa_response *alexa_response, char *boundary_term)
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
}


/* send data  */
ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    alexa_request *alexa_session = data_source->ptr;

    ssize_t bytes_written = 0;
    PART_TYPE next_action = alexa_session->next_action;

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

    printf("writing %d bytes to stream_id: %d, buf length: %d\n", bytes_written, stream_id, buf_length);
    // printf("%.*s\n", bytes_written, buf);

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
    alexa_session *alexa_session = session_data->user_data;

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
    alexa_session *alexa_session = session_data->user_data;

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

    alexa_session *alexa_session = calloc(1, sizeof(alexa_session));
    alexa_session->request = calloc(1, sizeof(alexa_request));
    alexa_session->request->next_action = META_HEADERS;
    alexa_session->response = calloc(1, sizeof(alexa_response));


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
