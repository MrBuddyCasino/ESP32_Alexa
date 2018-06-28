/*
 * alexa.c
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "nghttp2/nghttp2.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "multipart_parser.h"
#include "nghttp2_client.h"
#include "sntp.h"

#include "ui.h"
#include "audio_player.h"
#include "alexa.h"

#include "audio_recorder.h"
#include "controls.h"
#include "common_buffer.h"
#include "byteswap.h"
#include "alexa_directive_handler.h"
#include "multipart_producer.h"
#include "stream_handler_directives.h"
#include "stream_handler_events.h"
#include "sound_startup.h"
#include "url_parser.h"

#include "wifi.h"
#include "sdkconfig.h"


#include "asio.h"
#include "asio_http2.h"
#include "asio_gpio.h"
#include "asio_generic.h"
#include "asio_led_ui.h"
#include "alexa_events_js.h"
#include "alexa_speech_recognizer.h"
#include "alexa_events_send.h"

/**
 * Hide struct members from the public
 */
struct alexa_session_struct_t
{
    player_t *player_config;
    char *auth_token;
    EventGroupHandle_t event_group;
    alexa_stream_t *stream_directives;
    alexa_stream_t *stream_events;
    asio_registry_t *registry;
    int last_time_activity;
};

static alexa_session_t *alexa_session;

const int AUTH_TOKEN_VALID_BIT = BIT(2);
const int DOWNCHAN_CONNECTED_BIT = BIT(3);
const int INITIAL_STATE_SENT_BIT = BIT(4);
const int USER_ACTIVITY_PRESENCE_BIT = BIT(5);


/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives = ALEXA_ENDPOINT "/v20160207/directives";
static char *uri_events = ALEXA_ENDPOINT "/v20160207/events";

#define TAG "alexa"

#define BEARER "Bearer "
#define NL "\r\n"

/* embedded file */
extern uint8_t file_start[] asm("_binary_what_time_raw_start");
extern uint8_t file_end[] asm("_binary_what_time_raw_end");

/* forward-declare some stuff */
asio_result_t on_auth_token_valid_cb(asio_task_t *conn, void *arg, void *user_data);
asio_result_t on_downchan_connected_cb(asio_task_t *task, void *arg, void *user_data);



EventGroupHandle_t get_event_group(alexa_session_t *alexa_session)
{
    return alexa_session->event_group;
}

void *get_io_context(alexa_session_t *alexa_session)
{
    return alexa_session->registry;
}

player_t *get_player_config(alexa_session_t *alexa_session)
{
    return alexa_session->player_config;
}

alexa_stream_t *get_stream_events(alexa_session_t *alexa_session)
{
    return alexa_session->stream_events;
}

alexa_stream_t *get_stream_directives(alexa_session_t *alexa_session)
{
    return alexa_session->stream_directives;
}


/**
 * @brief Updates the authentication token. Takes ownership of access_token.
 */
void set_auth_token(alexa_session_t *alexa_session, char* access_token)
{
    if (alexa_session->auth_token != NULL) {
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

    asio_registry_init(&alexa_session->registry, NULL);
    alexa_session->event_group = xEventGroupCreate();

    // init player
    alexa_session->player_config = calloc(1, sizeof(player_t));
    alexa_session->player_config->command = CMD_NONE;
    alexa_session->player_config->decoder_status = UNINITIALIZED;
    alexa_session->player_config->decoder_command = CMD_NONE;
    alexa_session->player_config->buffer_pref = BUF_PREF_FAST;
    alexa_session->player_config->media_stream = calloc(1,
            sizeof(media_stream_t));
    alexa_session->player_config->media_stream->eof = true;
    alexa_session->player_config->media_stream->content_type = MIME_UNKNOWN;

    // init streams
    alexa_session->stream_directives = calloc(1, sizeof(alexa_stream_t));
    alexa_session->stream_directives->stream_type = STREAM_DIRECTIVES;
    alexa_session->stream_directives->alexa_session = alexa_session;
    alexa_session->stream_directives->status = CONN_CLOSED;
    alexa_session->stream_directives->stream_id = -1;
    alexa_session->stream_directives->msg_id = 1;
    alexa_session->stream_directives->dialog_req_id = 1;

    alexa_session->stream_events = calloc(1, sizeof(alexa_stream_t));
    alexa_session->stream_events->stream_type = STREAM_EVENTS;
    alexa_session->stream_events->alexa_session = alexa_session;
    alexa_session->stream_events->status = CONN_CLOSED;
    alexa_session->stream_events->stream_id = -1;
    alexa_session->stream_events->msg_id = 1;
    alexa_session->stream_events->dialog_req_id = 1;

    return 0;
}

/* receive header */
int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
        const uint8_t *name, size_t namelen, const uint8_t *value,
        size_t valuelen, uint8_t flags, void *user_data)
{
    http2_session_data_t *session_data = user_data;
    alexa_session_t *alexa_session = session_data->user_data;
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session,
            frame->hd.stream_id);

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                /* Print response headers for the initiated request. */
                printf("%s: %s\n", name, value);

                // check downchannel stream reply status
                if (frame->hd.stream_id
                        == alexa_session->stream_directives->stream_id) {
                    if (strcmp(":status", (char*) name) == 0) {
                        int status_code = atoi((const char *) value);
                        switch (status_code) {

                            case 403:
                                ESP_LOGE(TAG,
                                        "what do you mean my auth token is invalid?")
                                ;
                                xEventGroupClearBits(alexa_session->event_group,
                                        AUTH_TOKEN_VALID_BIT);
                                alexa_session->stream_directives->status =
                                        CONN_UNAUTHORIZED;
                                // auth_token_refresh(alexa_session);
                                // this will close the stream
                                // return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                                return 0;

                            case 200:
                                alexa_session->stream_directives->status =
                                        CONN_OPEN;
                                break;
                        }
                    }
                }

                // incoming response header terminates send speech
                else if (frame->hd.stream_id
                        == alexa_session->stream_events->stream_id) {
                    if (strcmp(":status", (char*) name) == 0) {
                        alexa_session->stream_events->next_action = DONE;
                        // int status_code = atoi((const char *) value);
                    }
                }

                // parse boundary term
                if (strcmp("content-type", (char*) name) == 0) {
                    char* start = strstr((char*) value, "boundary=");
                    if (start != NULL) {
                        start += strlen("boundary=");
                        char* end = strstr(start, ";");
                        if (end != NULL) {
                            // make room for '--' prefix
                            start -= 2;
                            char* boundary_term = strndup(start, end - start);
                            boundary_term[0] = '-';
                            boundary_term[1] = '-';

                            if (stream->stream_type == STREAM_DIRECTIVES)
                            {
                                stream_handler_directives_init_multipart_parser(
                                        stream, boundary_term);
                            }
                            else if (stream->stream_type == STREAM_EVENTS)
                            {
                                stream_handler_events_init_multipart_parser(
                                        stream, boundary_term);
                            }
                        }
                    }
                }
            }
            break;
    }

    return 0;
}

/* receive data */
int on_data_recv_callback(nghttp2_session *session, uint8_t flags,
        int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session,
            stream_id);

    // listen to what the goddess has to say
    if (stream->stream_type == STREAM_DIRECTIVES
            && stream->current_part != AUDIO_DATA) {
        // already printed by multipart parser
        printf("directives data:\n%.*s\n", len, data);
    }

    if (stream->stream_type == STREAM_EVENTS
            && stream->current_part != AUDIO_DATA) {
        // already printed by multipart parser
        printf("events data:\n%.*s\n", len, data);
    }

    // will be non-null after boundary term was detected
    if (stream->m_parser != NULL) {
        // ESP_LOGW(TAG, "multipart_parser_execute() stream_type=%d", stream->stream_type);
        if(stream->stream_type == STREAM_DIRECTIVES) {
            /*
            bool starts_with = strncmp("Content-Type", (char*) data, strlen("Content-Type")) == 0;

            if(starts_with) {
                multipart_parser_execute(stream->m_parser, stream->boundary, strlen(stream->boundary));
                multipart_parser_execute(stream->m_parser, NL, strlen(NL));
            }
            */
            // Amazon sends \r\n for downstream events - skip those
            bool starts_with = strncmp("\r\n--", (char*) data, strlen("\r\n--")) == 0;
            if(starts_with) {
                data += 2;
                len -= 2;
            }

        }
        multipart_parser_execute(stream->m_parser, (char*) data, len);
    }

    return 0;
}

int stream_close_callback(nghttp2_session *session, int32_t stream_id,
        uint32_t error_code, void *user_data)
{
    http2_session_data_t *session_data = user_data;
    alexa_stream_t *stream = nghttp2_session_get_stream_user_data(session,
            stream_id);

    ESP_LOGI(TAG, "closed stream %d with error_code=%u", stream_id, error_code);

    asio_http2_on_stream_close(session, stream_id, error_code, user_data);

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

static char* build_auth_header(char* auth_token)
{
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
    http2_session_data_t *session_data = user_data;
    alexa_session_t *alexa_session = session_data->user_data;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            print_headers(frame->headers.nva, frame->headers.nvlen);
            if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
                ESP_LOGI(TAG, "All headers received for stream %d",
                        frame->headers.hd.stream_id);

                if (frame->headers.hd.stream_id
                        == alexa_session->stream_directives->stream_id) {
                    // once all headers for the downchannel are received, we're clear
                    ESP_LOGI(TAG, "setting DOWNCHAN_CONNECTED_BIT");
                    xEventGroupSetBits(alexa_session->event_group,
                            DOWNCHAN_CONNECTED_BIT);
                }
            }
            break;

        case NGHTTP2_GOAWAY:
            // hacky workaround
            ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
            ESP_LOGI(TAG, "frame received: %u", frame->hd.type);
            nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, alexa_session->stream_directives->stream_id, NGHTTP2_STREAM_CLOSED);
            alexa_session->stream_directives->status = CONN_CLOSED;
            xEventGroupClearBits(alexa_session->event_group, DOWNCHAN_CONNECTED_BIT);
            auth_token_refresh(alexa_session);

            ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
            asio_new_generic_task("downchannel", alexa_session->registry, on_auth_token_valid_cb, alexa_session->event_group, alexa_session);
            /* send initial state when downchannel is connected */
            asio_new_generic_task("send_initial_state", alexa_session->registry, on_downchan_connected_cb, alexa_session->event_group, alexa_session);
            ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
            break;

        default:
            ESP_LOGI(TAG, "frame received: %u", frame->hd.type)
            ;
            break;

    }
    return 0;
}

int open_downchannel(alexa_session_t *alexa_session)
{
    int ret;
    http2_session_data_t *http2_session;

    alexa_session->stream_directives->next_action = META_HEADERS;

    char *auth_header = build_auth_header(alexa_session->auth_token);

    // add headers
    nghttp2_nv hdrs[1] = {
    MAKE_NV("authorization", auth_header, strlen(auth_header)) };

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
            on_header_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
            on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
            on_data_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
            stream_close_callback);

    ret = nghttp_new_session(&http2_session, uri_directives, "GET",
            &alexa_session->stream_directives->stream_id, hdrs, 1,
            NULL, callbacks,
            alexa_session->stream_directives, alexa_session);
    if (ret != 0) {
        free_http2_session_data(http2_session, ret);
        return ret;
    }

    free(auth_header);

    alexa_session->stream_directives->http2_session = http2_session;
    alexa_session->stream_events->http2_session = http2_session;

    /* start read write loop */
    //ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
    //xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task", 8192,
    //        http2_session, tskIDLE_PRIORITY + 1, NULL, 0);

    asio_registry_t *registry = get_io_context(alexa_session);
    ret = asio_new_http2_session(
            registry,
            http2_session,
            uri_directives);

    return ret;
}

int alexa_send_event(alexa_session_t *alexa_session,
        nghttp2_data_source_read_callback read_callback)
{

    // h2 will take ownership
    nghttp2_data_provider data_provider_struct = {
            .read_callback = read_callback,
            .source.ptr = alexa_session->stream_events
    };

    // add headers
    char *auth_header = build_auth_header(alexa_session->auth_token);
    // ESP_LOGI(TAG, "authorization length=%d value=%s", strlen(auth_header), auth_header);
    nghttp2_nv hdrs[2] = {
    MAKE_NV("authorization", auth_header, strlen(auth_header)),
    MAKE_NV2("content-type", HDR_FORM_DATA) };

    /* create stream */
    int ret = nghttp_new_stream(alexa_session->stream_directives->http2_session,
            &alexa_session->stream_events->stream_id,
            alexa_session->stream_events, uri_events, "POST", hdrs, 2,
            &data_provider_struct);

    free(auth_header);

    return ret;
}


void alexa_gpio_handler_task(gpio_handler_param_t *params)
{
    xQueueHandle gpio_evt_queue = params->gpio_evt_queue;
    alexa_session_t *alexa_session = params->user_data;

    uint32_t io_num;

    for (;;) {
        if (xQueueReceive(gpio_evt_queue, &io_num, portMAX_DELAY)) {
            printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
            ESP_LOGI(TAG, "RAM left %d", esp_get_free_heap_size());

            speech_recognizer_start_capture(alexa_session);
        }
    }

    vTaskDelete(NULL);
}

/*
 * reset inactivity "timer" and ping "timer"
 */
void update_last_action_time()
{
    xEventGroupSetBits(alexa_session->event_group, USER_ACTIVITY_PRESENCE_BIT);
}

void alexa_gpio_handler(gpio_num_t io_num, void *user_data)
{
    printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));

    alexa_session_t *alexa_session = user_data;

    update_last_action_time();
    
    if(speech_recognizer_is_ready()) {
        ui_queue_event(UI_RECOGNIZING_SPEECH);
        speech_recognizer_start_capture(alexa_session);
    }
}


asio_result_t on_auth_token_valid_cb(asio_task_t *conn, void *arg, void *user_data)
{
    EventGroupHandle_t event_group = arg;
    alexa_session_t *alexa_session = user_data;

    /* when we've got a valid auth token: open downchannel and terminate task */
    if(xEventGroupGetBits(event_group) & AUTH_TOKEN_VALID_BIT) {
        open_downchannel(alexa_session);
        conn->task_flags |= TASK_FLAG_TERMINATE;
    }

    return ASIO_OK;
}

asio_result_t on_downchan_connected_cb(asio_task_t *task, void *arg, void *user_data)
{
    EventGroupHandle_t event_group = arg;
    alexa_session_t *alexa_session = user_data;

    /* when the connection is established, synchronize state and terminate task */
    if(xEventGroupGetBits(event_group) & DOWNCHAN_CONNECTED_BIT) {
        event_send_state(alexa_session);
        event_send_settings_updated(alexa_session);
        // TODO
        play_sound(alexa_session->player_config);
        task->task_flags |= TASK_FLAG_TERMINATE;
    }

    return ASIO_OK;
}

/* start auth token refresh */
asio_result_t on_wifi_connected_cb(asio_task_t *task, void *arg, void *user_data)
{
    EventGroupHandle_t event_group = arg;
    alexa_session_t *alexa_session = user_data;

    if(xEventGroupGetBits(event_group) & CONNECTED_BIT) {
        ui_queue_event(UI_CONNECTED);

        // TODO
        obtain_time();

        auth_token_refresh(alexa_session);
        task->task_flags |= TASK_FLAG_TERMINATE;
    }

    return ASIO_OK;
}

/* send ping every around 5 minutes, "timer" is reset on user activity (ie push button) */
TickType_t last_wake_time;
#define TICKS_TO_DELAY 5 * 60 * 999  // its 999 ticks if is setup 1000 ticks in menuconfig 
asio_result_t delayed_server_ping_task(asio_task_t *task, void *arg, void *user_data)
{
    EventGroupHandle_t event_group = arg;
    alexa_session_t *alexa_session = user_data;

    if(!(xEventGroupGetBits(event_group) & USER_ACTIVITY_PRESENCE_BIT) && last_wake_time + TICKS_TO_DELAY <= xTaskGetTickCount())
    {
        nghttp2_session *session = alexa_session->stream_events->http2_session->h2_session;
        nghttp2_submit_ping(session, NGHTTP2_FLAG_NONE, NULL);
        last_wake_time = xTaskGetTickCount();
        ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());
        if((xTaskGetTickCount() - alexa_session->last_time_activity)/3600 > 0){
            //todo send UserInactiveReport every 1 hour inactivity of user in seconds rounded to full hour
        }
    }
    else if(xEventGroupGetBits(event_group) & USER_ACTIVITY_PRESENCE_BIT)
    {
        last_wake_time = xTaskGetTickCount();
        alexa_session->last_time_activity = last_wake_time;
        ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());            
        xEventGroupClearBits(event_group, USER_ACTIVITY_PRESENCE_BIT);
    }
    return ASIO_OK;
}



int alexa_init()
{
    ESP_LOGI(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    //alexa_session_t *alexa_session;
    create_alexa_session(&alexa_session);

    /* init led ui */
    asio_new_generic_task("led_ui", alexa_session->registry, on_led_ui_cb, GPIO_NUM_4, NULL);


    /* init wifi */
    ui_queue_event(UI_CONNECTING);
    initialise_wifi(alexa_session->event_group);

    // create I2S config
    // configure_audio_hw(alexa_session->player_config);

    asio_new_gpio_task(alexa_session->registry, CONFIG_ALEXA_GPIO_NUM, alexa_gpio_handler, alexa_session);

    /* refresh auth token when wifi is connected */
    asio_new_generic_task("refresh_auth_token", alexa_session->registry, on_wifi_connected_cb, alexa_session->event_group, alexa_session);
    ESP_LOGW(TAG, "%d: - RAM left %d", __LINE__, esp_get_free_heap_size());

    /* open downchannel when authentication token has been acquired */
    asio_new_generic_task("downchannel", alexa_session->registry, on_auth_token_valid_cb, alexa_session->event_group, alexa_session);

    /* send initial state when downchannel is connected */
    asio_new_generic_task("send_initial_state", alexa_session->registry, on_downchan_connected_cb, alexa_session->event_group, alexa_session);

    asio_new_generic_task("ping", alexa_session->registry, delayed_server_ping_task, alexa_session->event_group, alexa_session);
    // run event loop
    while(1) {
        asio_registry_poll(alexa_session->registry);
        vTaskDelay(1);
    }

    //ESP_LOGI(TAG, "alexa_init stack: %d\n", uxTaskGetStackHighWaterMark(NULL));

    return 0;
}
