/*
 * alexa.c
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "nghttp-client.h"
#include "cJSON.h"
#include "esp_log.h"

typedef enum
{
    META_HEADERS, META_JSON, AUDIO_HEADERS, AUDIO_DATA, DONE
} NEXT_ACTION;

typedef struct
{
    NEXT_ACTION next_action;
    uint8_t *file_pos;
} alexa_session;

/* Europe: alexa-eu / America: alexa-na */
static char *uri_directives =
        "https://avs-alexa-eu.amazon.com/v20160207/directives";
static char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";

#define TAG "alexa"

#define NL "\r\n"
#define TOKEN "Bearer Atza|IwEBIDqdQoAHTirZBVKJ58usrUY6DrDk4WgDGAxQuWSWSRMM8jU2MpXUZowKzCyi1BX1DPXqvrv9lVVYL5AVnM3wOnaQRHFSFCFr6Nkg-IeOs7uz_Fxdv4vXM_YVf9rJ-lukQm6elxalCm9HsjsmKkfFW_9wZHZihQNhUpO0UUPBefmel1YMZn9h5a3V4swBRJD0G0XeBh8g7rY_PXbeCizQk46CS8HvmpyH0HkmGv7PrNwXgH3eUCZRA-YGMM55oH5dCkLwbU9kd-SeKl-32LKYPX_y3QsKlkfDk0R2iAEgmxMIDHBAl-Phl-mVjCWWpWxwDddP43zml63--n6uYrSyxv4ezrXPccyEsIG-vLCuY70-fgnP0iT1QwHkVnOg-YoZTRoGMhLp5Jgv2t-eh2ayaMm_GETGvsE077lhAWXtw53sHhzvliBh5DHATDDSW_lZigStqOm2vthO4LyGrh-ENak_1CofL7T8XiBFxfc8e7iy9OAd4i8pZTBJCy71vzDwSl3eHqoE4SmSH58bVdatUrsKkHzKM85LjSqA-W0o7BDV8A"
#define BOUNDARY_TERM "nghttp2123456789"
#define BOUNDARY_LINE "--" BOUNDARY_TERM NL
#define BOUNDARY_EOF BOUNDARY_LINE "--"
#define HDR_FORM_DATA "multipart/form-data; boundary=" BOUNDARY_TERM

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

static bool did_yield = true;

/* send data  */
ssize_t data_source_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *) user_data;
    alexa_session *alexa_session = data_source->ptr;

    ssize_t bytes_written = 0;
    NEXT_ACTION next_action = alexa_session->next_action;

    if(!did_yield) {
        did_yield = true;
        // return NGHTTP2_ERR_DEFERRED;
        // return NGHTTP2_ERR_WOULDBLOCK;
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
            // *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            // alexa_session->next_action = DONE;
            if(alexa_session->next_action == DONE)
                break;


            if(alexa_session->file_pos == 0)
                alexa_session->file_pos = file_start;

            uint8_t *pos = alexa_session->file_pos;
            // size_t file_size = file_end - file_start;
            size_t remaining = file_end - pos;
            bytes_written = buf_length < remaining ? buf_length : remaining;
            memcpy(buf, pos, bytes_written);

            if(buf_length > remaining) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                alexa_session->next_action = DONE;
            } else {
                *data_flags |= NGHTTP2_DATA_FLAG_NONE;
            }

            alexa_session->file_pos += bytes_written;

            break;

        case DONE:
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            break;
    }

    printf("writing %d bytes to stream_id: %d, buf length: %d\n", bytes_written, stream_id, buf_length);
    printf("%.*s\n", bytes_written, buf);

    return bytes_written;
}


/* receive data */
int recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    printf("%.*s", len, data);
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
    alexa_session->next_action = META_HEADERS;
    // http2_session->user_data = alexa_session;


    nghttp2_data_provider *data_provider_struct = calloc(1,
            sizeof(nghttp2_data_provider));
    data_provider_struct->read_callback = data_source_read_callback;
    data_provider_struct->source.ptr = alexa_session;

    // add headers
    nghttp2_nv hdrs[2] = {
            MAKE_NV2("authorization", TOKEN),
            MAKE_NV2("content-type", HDR_FORM_DATA)
    };

    esp_err_t ret = nghttp_new_session(&http2_session, uri_events, "POST",
            hdrs, 2, data_provider_struct, recv_callback,
            stream_close_callback);

    // has now been copied by nghttp2
    free(data_provider_struct);

    if(ret != 0)
        return;

    // submit_request(http2_session, user_hdrs, 1, method, data_provider_struct);
}
