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
#include "esp_system.h"
#include "esp_log.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"

#include "alexa.h"
#include "audio_player.h"
#include "audio_recorder.h"
#include "controls.h"
#include "common_buffer.h"
#include "byteswap.h"
#include "alexa_directive_handler.h"
#include "alexa_events.h"
#include "multipart_producer.h"
#include "event_send_speech.h"
#include "event_send_state.h"




/**
 * Hide struct members from the public
 */
struct alexa_session_struct_t
{
    player_t *player_config;
    char *auth_token;
    EventGroupHandle_t event_group;
    alexa_stream_t *downchannel;
    alexa_stream_t *eventchannel;
};


static alexa_session_t *alexa_session;

const int AUTH_TOKEN_VALID_BIT = BIT(1);
const int DOWNCHAN_CONNECTED_BIT = BIT(3);


/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives =
        "https://avs-alexa-eu.amazon.com/v20160207/directives";
static char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";

#define TAG "alexa"

#define BEARER "Bearer "
#define NL "\r\n"

/* embedded file */
extern uint8_t file_start[] asm("_binary_what_time_raw_start");
extern uint8_t file_end[] asm("_binary_what_time_raw_end");

/**
 * @brief Updates the authentication token. Takes ownership of access_token.
 */
void set_auth_token(alexa_session_t *alexa_session, char* access_token)
{
    if(alexa_session->auth_token != NULL) {
        free(alexa_session->auth_token);
    }
    // alexa_session->auth_token = strdup(access_token);
    alexa_session->auth_token = access_token;

    ESP_LOGI(TAG, "new auth_token: %s", access_token);
}


static int create_alexa_session(alexa_session_t **alexa_session_ptr)
{
    (*alexa_session_ptr) = calloc(1, sizeof(struct alexa_session_struct_t));
    alexa_session_t *alexa_session = (*alexa_session_ptr);

    alexa_session->event_group = xEventGroupCreate();

    // init player
    alexa_session->player_config = calloc(1, sizeof(player_t));
    alexa_session->player_config->command = CMD_NONE;
    alexa_session->player_config->decoder_status = UNINITIALIZED;
    alexa_session->player_config->decoder_command = CMD_NONE;
    alexa_session->player_config->buffer_pref = BUF_PREF_FAST;
    alexa_session->player_config->media_stream = calloc(1, sizeof(media_stream_t));
    alexa_session->player_config->media_stream->eof = true;
    alexa_session->player_config->media_stream->content_type = MIME_UNKNOWN;

    // init streams
    alexa_session->downchannel = calloc(1, sizeof(alexa_stream_t));
    alexa_session->downchannel->stream_type = STREAM_DOWNCHAN;
    alexa_session->downchannel->alexa_session = alexa_session;
    alexa_session->downchannel->status = CONN_CLOSED;
    alexa_session->downchannel->stream_id = -1;
    alexa_session->downchannel->msg_id = 1;
    alexa_session->downchannel->dialog_req_id = 1;


    alexa_session->eventchannel = calloc(1, sizeof(alexa_stream_t));
    alexa_session->eventchannel->stream_type = STREAM_EVT;
    alexa_session->eventchannel->alexa_session = alexa_session;
    alexa_session->eventchannel->status = CONN_CLOSED;
    alexa_session->eventchannel->stream_id = -1;
    alexa_session->eventchannel->msg_id = 1;
    alexa_session->eventchannel->dialog_req_id = 1;

    return 0;
}


/* multipart callbacks */
int on_multipart_header_field(multipart_parser *parser, const char *at, size_t length)
{
    // alexa_response_t *alexa_response = multipart_parser_get_data(parser);

    printf("on_header_field %.*s\n", (int)length, at);
    return 0;
}

int on_multipart_header_value(multipart_parser *parser, const char *at, size_t length)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    printf("on_header_value %.*s\n", (int)length, at);

    // assumes audio on application/octet-stream
    if(strncmp("application/octet-stream", at, length) == 0) {
        printf("audio part detected\n");
        alexa_stream->current_part = AUDIO_DATA;
        alexa_session->player_config->media_stream->eof = false;
        alexa_session->player_config->media_stream->content_type = AUDIO_MPEG;

        printf("starting player\n");
        audio_player_start(alexa_session->player_config);
    }
    else if (strncmp("application/json; charset=UTF-8", at, length) == 0) {
        printf("directive detected\n");
        alexa_stream->current_part = META_JSON;
    }

    return 0;
}

static buffer_t *json_buf = NULL;
int on_multipart_data(multipart_parser *parser, const char *at, size_t length)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    if(alexa_stream->current_part == AUDIO_DATA)
    {
        // ESP_LOGI("feeding player\n");
        audio_stream_consumer(at, length, alexa_session->player_config);
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
int on_multipart_data_begin(multipart_parser *parser)
{
    printf("on_part_data_begin\n");
    return 0;
}

int on_multipart_headers_complete(multipart_parser *parser)
{
    printf("on_headers_complete\n"); return 0;
}

int on_multipart_data_end(multipart_parser *parser)
{
    alexa_stream_t *alexa_stream = multipart_parser_get_data(parser);
    alexa_session_t *alexa_session = alexa_stream->alexa_session;

    printf("on_part_data_end\n");

    if(alexa_stream->current_part == AUDIO_DATA) {
        alexa_session->player_config->media_stream->eof = true;
        // ensure flush
        audio_stream_consumer(NULL, 0, alexa_session->player_config);
    }

    if(alexa_stream->current_part == META_JSON) {
        handle_directive((const char *) json_buf->base, json_buf->len);
        buf_destroy(json_buf);
        json_buf = NULL;
    }

    return 0;
}

int on_multipart_body_end(multipart_parser *parser)
{
    printf("on_body_end\n");
    // MAD and NGHTTP2 terminate themselves - shutdown renderer?
    return 0;
}

void init_multipart_parser(alexa_stream_t *alexa_stream, char *boundary_term)
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




/* receive header */
int on_header_callback(nghttp2_session *session,
                      const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen,
                      uint8_t flags, void *user_data)
{
    http2_session_data_t *session_data = user_data;
    alexa_session_t *alexa_session = session_data->user_data;
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

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
                            ESP_LOGE(TAG, "what do you mean my auth token is invalid?");
                            xEventGroupClearBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT);
                            alexa_session->downchannel->status = CONN_UNAUTHORIZED;
                            // auth_token_refresh(alexa_session);
                            // this will close the stream
                            // return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                            return 0;

                        case 200:
                            alexa_session->downchannel->status = CONN_OPEN;
                        break;
                    }
                }
            }

            // incoming response header terminates send speech
            else if(frame->hd.stream_id == alexa_session->eventchannel->stream_id) {
                if(strcmp(":status", (char*) name) == 0)
                {
                    alexa_session->eventchannel->next_action = DONE;
                    // int status_code = atoi((const char *) value);
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
                        init_multipart_parser(stream, boundary_term);
                    }
                }
            }
        }
        break;
    }

    return 0;
}


/* receive data */
int on_data_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);

    // listen what the goddess has to say
    if(stream->stream_type == STREAM_DOWNCHAN && stream->current_part != AUDIO_DATA) {
        // already printed by multipart parser
        printf("downchannel data:\n%.*s\n", len, data);
    }

    if(stream->stream_type == STREAM_EVT && stream->current_part != AUDIO_DATA) {
        // already printed by multipart parser
        printf("event data:\n%.*s\n", len, data);
    }

    // will be non-null after boundary term was detected
    if(stream->m_parser != NULL) {
        multipart_parser_execute(stream->m_parser, (char*)data, len);
    }

    return 0;
}


int stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    http2_session_data_t *session_data = user_data;
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session, stream_id);

    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);
    stream->status = CONN_CLOSED;

    session_data->num_outgoing_streams--;
    if (session_data->num_outgoing_streams < 1) {
        ESP_LOGE(TAG, "no more open streams, terminating session");
        nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);
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

    //renderer_init(create_renderer_config());

    // init recorder

    // init i2s player
    audio_player_init(alexa_session->player_config);
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
    http2_session_data_t *session_data  = user_data;
    alexa_session_t *alexa_session = session_data->user_data;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            print_headers(frame->headers.nva, frame->headers.nvlen);
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                ESP_LOGI(TAG, "All headers received for stream %d", frame->headers.hd.stream_id);

                if(frame->headers.hd.stream_id == alexa_session->downchannel->stream_id) {
                    // once all headers for the downchannel are received, we're clear
                    ESP_LOGI(TAG, "setting DOWNCHAN_CONNECTED_BIT");
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
    http2_session_data_t *http2_session;

    alexa_session->downchannel->next_action = META_HEADERS;

    char *auth_header = build_auth_header(alexa_session->auth_token);

    // add headers
    nghttp2_nv hdrs[1] = {
            MAKE_NV("authorization", auth_header, strlen(auth_header))
    };

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_close_callback);

    ret = nghttp_new_session(&http2_session,
                uri_directives, "GET",
                &alexa_session->downchannel->stream_id,
                hdrs, 1,
                NULL,
                callbacks,
                alexa_session->downchannel,
                alexa_session);
    if(ret != 0) {
        free_http2_session_data(http2_session, ret);
        return ret;
    }

    free(auth_header);

    alexa_session->downchannel->http2_session = http2_session;
    alexa_session->eventchannel->http2_session = http2_session;

    /* start read write loop */
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task", 8192, http2_session, tskIDLE_PRIORITY + 1, NULL, 0);

    return ret;
}

int net_send_event(alexa_session_t *alexa_session, nghttp2_data_source_read_callback read_callback)
{

    // h2 will take ownership
    nghttp2_data_provider data_provider_struct = {
            .read_callback = read_callback,
            .source.ptr = alexa_session->eventchannel
    };

    // add headers
    char *auth_header = build_auth_header(alexa_session->auth_token);
    // ESP_LOGI(TAG, "authorization length=%d value=%s", strlen(auth_header), auth_header);
    nghttp2_nv hdrs[2] = {
            MAKE_NV("authorization", auth_header, strlen(auth_header)),
            MAKE_NV2("content-type", HDR_FORM_DATA)
    };

    /* create stream */
    int ret = nghttp_new_stream(alexa_session->downchannel->http2_session,
            &alexa_session->eventchannel->stream_id,
            alexa_session->eventchannel,
            uri_events, "POST",
            hdrs, 2,
            &data_provider_struct);

    free(auth_header);

    return ret;
}

int send_speech(alexa_session_t *alexa_session)
{
    alexa_session->eventchannel->next_action = META_HEADERS;
    alexa_session->eventchannel->file_pos = 0;
    alexa_session->eventchannel->current_part = META_HEADERS;

    return net_send_event(alexa_session, send_speech_read_callback);
}

typedef enum { START_SEND_SPEECH, STOP_SEND_SPEECH } alexa_action_t;
alexa_action_t next_action = START_SEND_SPEECH;
void alexa_gpio_handler_task(void *pvParams)
{
    gpio_handler_param_t *params = pvParams;
    xQueueHandle gpio_evt_queue = params->gpio_evt_queue;
    alexa_session_t *alexa_session = params->user_data;

    uint32_t io_num;

    for(;;) {
        if(xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
            ESP_LOGI(TAG, "RAM left %d", esp_get_free_heap_size());

            switch (next_action)
            {
                case START_SEND_SPEECH:
                    next_action = STOP_SEND_SPEECH;
                    renderer_start();
                    audio_recorder_start();
                    send_speech(alexa_session);
                    break;

                case STOP_SEND_SPEECH:
                    alexa_session->eventchannel->next_action = DONE;
                    next_action = START_SEND_SPEECH;
                    audio_recorder_stop();
                    renderer_stop();
                    break;
            }
        }
    }
}

int alexa_init()
{
    ESP_LOGI(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    //alexa_session_t *alexa_session;
    create_alexa_session(&alexa_session);

    // create I2S config
    // configure_audio_hw(alexa_session->player_config);

    controls_init(alexa_gpio_handler_task, 4096, alexa_session);

    // assume expired token
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    auth_token_refresh(alexa_session);
    ESP_LOGI(TAG, "auth_token_refresh finished");
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    //xEventGroupWaitBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT,
    //                            false, true, portMAX_DELAY);
    // vTaskDelay( 10 / portTICK_PERIOD_MS );
    // conn should remain open
    open_downchannel(alexa_session);
    ESP_LOGI(TAG, "open_downchannel finished");
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    // wait until downchannel is connected
    xEventGroupWaitBits(alexa_session->event_group, DOWNCHAN_CONNECTED_BIT,
                            false, true, portMAX_DELAY);

    // vTaskDelay( 10 / portTICK_PERIOD_MS );

    // send initial state
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    event_send_state(alexa_session);
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    // send voice
    // send_speech(alexa_session);

    // ESP_LOGI(TAG, "alexa_init stack: %d\n", uxTaskGetStackHighWaterMark(NULL));

    return 0;
}
