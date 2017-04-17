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
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"

#include "audio_player.h"
#include "controls.h"
#include "alexa.h"


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
} alexa_response_t;

typedef struct {
    alexa_request_t *request;
    alexa_response_t *response;
} exchange_t;


static alexa_session_t *alexa_session;
static http2_session_data *http2_session;

const int AUTH_TOKEN_VALID_BIT = BIT(1);
const int DOWNCHAN_CONNECTED_BIT = BIT(3);


/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives =
        "https://avs-alexa-eu.amazon.com/v20160207/directives";
static char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";

#define TAG "alexa"

#define BEARER "Bearer "
#define NL "\r\n"
#define REFRESH_TOKEN "Atzr|IwEBINGvR3LnNv9DLvCBuwN1JSc-A3NTnxVCzpuGcKra50U6jDx9ONI4X3b1VoQBedw5IFIr7MAttml0Zl3ONi73kjusEviQ6TiQeMyFNCyLt_XKy-iX000NiIqdrbNtNNCCZuVTYfARc8NLwFGfiz75tp7KLrgFpO2RK8VpcS9fchl9OEA_tMGzdypy_P2PHcAoGdp4-HUXRKeIBRiJ30TB7EqFypSp_PUqmLLQhnk3NsWa7TJYT3QaMXDBWPeZSRJnfHn_deWRoiP1oAA-BOfUz3E_F8HymVIiXT6XY4Fu2nZ7ZcBymreiIXmQz_ZySf-oyLBQdkZChYdjheyol7zX9n_jTGHKXZib7NSZcvDg3V2eul6qJdSZNRGVPE5gfyBDDXbTUe6UQQaOxQkaJVFJnkFX7MI_vv7fpw0GJTtX24y3OVptOuvr2ovkaglHFGXLT9CvEbjioCEROalK4C29EKZAgo9iWHCAre9xHYSfIfZ8_vZ4-xWHHECwYEBtW_7gkzXU0jXq6EKJ9TTFzekMoLK_"
#define REFRESH_TOKEN_URI "http://alexa.boeckling.net/auth/refresh/" REFRESH_TOKEN

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
extern uint8_t file_start[] asm("_binary_what_time_raw_start");
extern uint8_t file_end[] asm("_binary_what_time_raw_end");



static int create_alexa_session()
{
    alexa_session = calloc(1, sizeof(alexa_session_t));

    alexa_session->event_group = xEventGroupCreate();

    // init player
    alexa_session->player_config = calloc(1, sizeof(player_t));
    alexa_session->player_config->state = IDLE;
    alexa_session->player_config->buffer_pref = FAST;

    // init rest
    alexa_session->downchannel = calloc(1, sizeof(alexa_stream_t));
    alexa_session->downchannel->status = CONN_CLOSED;

    return 0;
}

/*
static int destroy_alexa_session(alexa_session_t *session)
{
    free(session->request);
    free(session->response);
    free(session);

    return 0;
}
*/

alexa_session_t *get_alexa_session()
{
    return alexa_session;
}


http2_session_data *get_http2_session()
{
    return http2_session;
}

void set_http2_session(http2_session_data *session)
{
    http2_session = session;
}


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



/* multipart callbacks */
int on_header_field(multipart_parser *parser, const char *at, size_t length)
{
    // alexa_response_t *alexa_response = multipart_parser_get_data(parser);

    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}

int on_header_value(multipart_parser *parser, const char *at, size_t length)
{
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = get_alexa_session();

    // assumes audio on application/octet-stream
    if(strncmp("application/octet-stream", at, length) == 0) {
        printf("audio part detected\n");
        alexa_response->current_part = AUDIO_DATA;

        printf("starting player\n");
        audio_player_init(alexa_session->player_config);
        audio_player_start(alexa_session->player_config);
    }

    printf("on_header_value %.*s\n", (int)length, at);

    return 0;
}

int on_part_data(multipart_parser *parser, const char *at, size_t length)
{
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = get_alexa_session();

    if(alexa_response->current_part == AUDIO_DATA)
    {
        // printf("feeding player\n");
        audio_stream_consumer(at, length, alexa_session->player_config);
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

int on_headers_complete(multipart_parser *parser)
{
    printf("on_headers_complete\n"); return 0;
}

int on_part_data_end(multipart_parser *parser)
{
    alexa_response_t *alexa_response = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = get_alexa_session();

    printf("on_part_data_end\n");

    if(alexa_response->current_part == AUDIO_DATA) {
        printf("stopping player\n");
        alexa_session->player_config->state = FINISHED;
        // audio_player_stop(alexa_response->player_config);
    }

    return 0;
}

int on_body_end(multipart_parser *parser)
{
    printf("on_body_end\n");
    // MAD and NGHTTP2 terminate themselves - shutdown renderer?
    return 0;
}

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
static bool yield = false;
ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{
    alexa_request_t *alexa_request = data_source->ptr;

    ssize_t bytes_written = 0;
    part_type_t next_action = alexa_request->next_action;

    if(yield) {
        yield = false;
        return NGHTTP2_ERR_DEFERRED;
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

            alexa_request->next_action = AUDIO_HEADERS;
            break;

        case AUDIO_HEADERS:
            bytes_written = strlen(AUDIO_PART_PREFIX);
            memcpy(buf, AUDIO_PART_PREFIX, bytes_written);
            alexa_request->next_action = AUDIO_DATA;
            break;

        case AUDIO_DATA:

            if(alexa_request->file_pos == 0)
                alexa_request->file_pos = file_start;

            uint8_t *pos = alexa_request->file_pos;
            // size_t file_size = file_end - file_start;
            size_t remaining = file_end - pos;
            bytes_written = buf_length < remaining ? buf_length : remaining;
            memcpy(buf, pos, bytes_written);

            if(buf_length > remaining) {
                alexa_request->next_action = DONE;
            } else {
                yield = true;
            }

            alexa_request->file_pos += bytes_written;

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


typedef struct {
    char *buf;
    size_t len;
} buffer_t;

int auth_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    // alexa_session_t *alexa_session = user_data;
    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    // grow the buffer
    // If the ptr argument is NULL, realloc acts like malloc()
    buffer->buf = realloc(buffer->buf, buffer->len + len);

    if(buffer->buf == NULL) {
        // TODO: insufficient memory for reallocation
    }

    memcpy((buffer->buf) + (buffer->len), data, len);
    buffer->len += len;

    return 0;
}

int auth_on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data)
{
    alexa_session_t *alexa_session = user_data;
    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    buffer->buf = realloc(buffer->buf, buffer->len + 1);
    buffer->buf[buffer->len] = '\0';

    cJSON *root = cJSON_Parse(buffer->buf);
    cJSON *token_item = cJSON_GetObjectItem(root, "access_token");
    char *access_token = token_item->valuestring;

    if(alexa_session->auth_token != NULL) {
        free(alexa_session->auth_token);
    }
    alexa_session->auth_token = strdup(access_token);

    cJSON_Delete(root);
    free(buffer->buf);
    free(buffer);

    xEventGroupSetBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT);

    return 0;
}

/* get a new authentication token */
void auth_token_refresh(alexa_session_t *alexa_session)
{
    // char *uri = "http://alexa.boeckling.net/auth/refresh/" REFRESH_TOKEN;

    buffer_t *buffer = calloc(1, sizeof(buffer_t));
    buffer->len = 0;

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, auth_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, auth_on_stream_close_callback);

    http2_session_data *http2_session_auth;
    int ret = nghttp_new_session(&http2_session_auth,
                    REFRESH_TOKEN_URI, "GET",
                    NULL, 0,
                    NULL,
                    callbacks,
                    buffer,
                    alexa_session);

    if(ret != 0) {
        // TODO
    }

    xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task_auth", 8192, http2_session_auth, 1, NULL, 0);
}

/* receive header */
int header_callback(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen,
                      uint8_t flags, void *user_data)
{

    alexa_session_t *alexa_session = get_alexa_session();
    exchange_t *exchange =
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
        if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            /* Print response headers for the initiated request. */
            printf("%s: %s\n", name, value);

            // check downchannel stream reply status
            if(frame->hd.stream_id == alexa_session->downchannel->stream_id) {
                if(strcmp(":status", (char*) name) == 0) {
                    int status_code = atoi((const char *) value);
                    switch(status_code) {

                        case 403:
                            xEventGroupClearBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT);
                            alexa_session->downchannel->status = CONN_UNAUTHORIZED;
                            auth_token_refresh(alexa_session);
                            // this will close the stream
                            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

                        case 200:
                            alexa_session->downchannel->status = CONN_OPEN;
                        break;
                    }
                }
            }

            // parse boundary term
            if(strcmp("content-type", (char*) name) == 0) {
                char* start = strstr((char*) value, "boundary=");
                if(start != NULL) {
                    start += strlen("boundary=");
                    char* end = strstr(start, ";");
                    if(end != NULL) {
                        // make room for '--' prefix
                        start -= 2;
                        char* boundary_term = strndup(start, end - start);
                        boundary_term[0] = '-';
                        boundary_term[1] = '-';
                        init_multipart_parser(exchange->response, boundary_term);
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
    exchange_t *exchange = nghttp2_session_get_stream_user_data(session, stream_id);

    // will be non-null after boundary term was detected
    if(exchange->response->m_parser != NULL) {
        multipart_parser_execute(exchange->response->m_parser, (char*)data, len);
    }

    // printf("%.*s", len, data);
    return 0;
}


int stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);

    // req/res cycle has finished
    exchange_t *exchange = nghttp2_session_get_stream_user_data(session, stream_id);
    free(exchange);

    http2_session_data *session_data = get_http2_session();
    session_data->num_outgoing_streams--;
    if (session_data->num_outgoing_streams < 1) {
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

static void print_header(const uint8_t *name, size_t namelen,
        const uint8_t *value, size_t valuelen)
{
    printf("%s: %s\n", name, value);
}

/* Print HTTP headers to |f|. Please note that this function does not
 take into account that header name and value are sequence of
 octets, therefore they may contain non-printable characters. */
static void print_headers(nghttp2_nv *nva, size_t nvlen)
{
    size_t i;
    for (i = 0; i < nvlen; ++i) {
        print_header(nva[i].name, nva[i].namelen, nva[i].value,
                nva[i].valuelen);
    }
    printf("\n");
}

void configure_audio_hw(player_t *player_config)
{
    // init renderer
    renderer_config_t *renderer_config = calloc(1, sizeof(renderer_config_t));
    renderer_config->bit_depth = I2S_BITS_PER_SAMPLE_16BIT;
    renderer_config->i2s_num = I2S_NUM_0;
    renderer_config->sample_rate = 44100;
    renderer_config->output_mode = I2S;
    renderer_config->sample_rate_modifier = 1.0;
    player_config->renderer_config = renderer_config;

    // init recorder
}

static char* build_auth_header(char* auth_token) {
    size_t buf_len = strlen(BEARER) + strlen(auth_token) + 1;
    char *auth_header = calloc(buf_len, sizeof(char));
    strcpy(auth_header, BEARER);
    strcpy(auth_header + strlen(BEARER), auth_token);

    return auth_header;
}


/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
 received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session,
        const nghttp2_frame *frame, void *user_data)
{
    alexa_session_t *alexa_session = user_data;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            print_headers(frame->headers.nva, frame->headers.nvlen);
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                ESP_LOGI(TAG, "All headers received");

                if(frame->headers.hd.stream_id == alexa_session->downchannel->stream_id) {
                    // once all headers for the downchannel are received, we're clear
                    xEventGroupSetBits(alexa_session->event_group, DOWNCHAN_CONNECTED_BIT);
                }
            }
            break;

        default:
            ESP_LOGI(TAG, "frame received: %u", frame->hd.type);
            break;

    }
    return 0;
}


int open_downchannel(alexa_session_t *alexa_session)
{
    int ret;
    http2_session_data *http2_session;

    exchange_t *exchange = calloc(1, sizeof(exchange_t));
    exchange->request = calloc(1, sizeof(alexa_request_t));
    exchange->request->next_action = META_HEADERS;
    exchange->response = calloc(1, sizeof(alexa_response_t));

    // authenticate
    if(alexa_session->auth_token == NULL) {
        ESP_LOGI(TAG, "auth token null, authenticating");
        auth_token_refresh(alexa_session);
        xEventGroupWaitBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT,
                                    false, true, portMAX_DELAY);
    }

    char *auth_header = build_auth_header(alexa_session->auth_token);

    // add headers
    nghttp2_nv hdrs[1] = {
            MAKE_NV2("authorization", auth_header)
    };

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_close_callback);

    ret = nghttp_new_session(&http2_session,
                uri_directives, "GET",
                hdrs, 1,
                NULL,
                callbacks,
                exchange,
                alexa_session);

    set_http2_session(http2_session);

    /* start read write loop */
    xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task", 8192, http2_session, 1, NULL, 0);

    return ret;
}

int send_speech(http2_session_data *http2_session)
{
    exchange_t *exchange = calloc(1, sizeof(exchange_t));
    exchange->request = calloc(1, sizeof(alexa_request_t));
    exchange->request->next_action = META_HEADERS;
    exchange->response = calloc(1, sizeof(alexa_response_t));

    nghttp2_data_provider *data_provider_struct = calloc(1,
                sizeof(nghttp2_data_provider));
    data_provider_struct->read_callback = data_source_read_callback;
    data_provider_struct->source.ptr = exchange->request;

    // add headers
    char *auth_header = build_auth_header(alexa_session->auth_token);
    nghttp2_nv hdrs[2] = {
            MAKE_NV2("authorization", auth_header),
            MAKE_NV2("content-type", HDR_FORM_DATA)
    };


    int ret = nghttp_new_stream(http2_session,
            exchange,
            uri_events, "POST",
            hdrs, 2,
            data_provider_struct);

    // struct has now been copied by nghttp2
    free(data_provider_struct);

    return ret;
}

void alexa_gpio_handler_task(void *pvParams)
{
    gpio_handler_param_t *params = pvParams;
    xQueueHandle gpio_evt_queue = params->gpio_evt_queue;

    uint32_t io_num;
    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));

            send_speech(get_http2_session());
        }
    }
}

int alexa_init()
{
    create_alexa_session();
    alexa_session_t *alexa_session = get_alexa_session();

    // create I2S config
    configure_audio_hw(get_alexa_session()->player_config);

    controls_init(alexa_gpio_handler_task, 4096, alexa_session);

    // conn should remain open
    open_downchannel(alexa_session);

    // wait until downchannel is connected
    xEventGroupWaitBits(alexa_session->event_group, DOWNCHAN_CONNECTED_BIT,
                            false, true, portMAX_DELAY);

    // send voice
    send_speech(get_http2_session());

    return 0;
}
