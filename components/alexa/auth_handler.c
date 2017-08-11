/*
 * auth_handler.c
 *
 *  Created on: 21.04.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "nghttp2/nghttp2.h"
#include "cJSON.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"

#include "audio_player.h"
#include "alexa.h"
#include "common_buffer.h"
#include "url_parser.h"
#include "asio.h"
#include "asio_http2.h"

#define TAG "auth_handler"


#define REFRESH_TOKEN CONFIG_ALEXA_AUTH_REFRESH_TOKEN
#define REFRESH_TOKEN_URI "https://alexa.boeckling.net/auth/refresh/" REFRESH_TOKEN


int auth_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    // grow the buffer
    if(len > buf_free_capacity_after_purge(buffer)) {
        if(buf_resize(buffer, buffer->len + len) != 0) {
            // TODO: insufficient memory for reallocation
            return -1;
        }
    }

    buf_write(buffer, data, len);

    return 0;
}

int auth_on_stream_close_callback(nghttp2_session *session,
                                    int32_t stream_id,
                                    uint32_t error_code,
                                    void *user_data)
{
    http2_session_data_t *session_data = user_data;
    alexa_session_t *alexa_session = session_data->user_data;

    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    //buffer->buf = realloc(buffer->buf, buffer->len + 1);
    //buffer->buf[buffer->len] = '\0';

    cJSON *root = cJSON_Parse((const char*)buffer->read_pos);
    cJSON *token_item = cJSON_GetObjectItem(root, "access_token");
    char *access_token = token_item->valuestring;

    //alexa_session->auth_token = access_token;

    set_auth_token(alexa_session, strdup(access_token));

    cJSON_Delete(root);
    buf_destroy(buffer);

    // nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);

    EventGroupHandle_t event_group = get_event_group(alexa_session);
    xEventGroupSetBits(event_group, AUTH_TOKEN_VALID_BIT);

    asio_http2_on_stream_close(session, stream_id, error_code, user_data);

    return 0;
}


/* get a new authentication token */
void auth_token_refresh(alexa_session_t *alexa_session)
{
    // char *uri = "http://alexa.boeckling.net/auth/refresh/" REFRESH_TOKEN;

    buffer_t *buffer = buf_create(256);

    nghttp2_session_callbacks *callbacks;
    create_default_callbacks(&callbacks);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, auth_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, auth_on_stream_close_callback);

    http2_session_data_t *http2_session_auth;
    int32_t stream_id;
    int ret = nghttp_new_session(&http2_session_auth,
                    REFRESH_TOKEN_URI, "GET",
                    &stream_id,
                    NULL, 0,
                    NULL,
                    callbacks,
                    buffer,
                    alexa_session);

    if(ret != 0) {
        free_http2_session_data(http2_session_auth, ret);
        ESP_LOGI(TAG, "nghttp_new_session finished with %d", ret);
        return;
    }

    asio_registry_t *registry = get_io_context(alexa_session);
    asio_new_http2_session(
            registry,
            http2_session_auth,
            REFRESH_TOKEN_URI);

    // ret = read_write_loop(http2_session_auth);
    // ESP_LOGI(TAG, "auth_token_refresh event loop finished with %d", ret);
    // free_http2_session_data(http2_session_auth, ret);

    // xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task_auth", 8192, http2_session_auth, 1, NULL, 0);
}
