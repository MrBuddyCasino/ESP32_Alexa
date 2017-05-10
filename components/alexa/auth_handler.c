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

#include "nghttp2/nghttp2.h"
#include "nghttp2_client.h"
#include "cJSON.h"
#include "alexa.h"

#define TAG "auth_handler"


#define REFRESH_TOKEN "Atzr|IwEBINGvR3LnNv9DLvCBuwN1JSc-A3NTnxVCzpuGcKra50U6jDx9ONI4X3b1VoQBedw5IFIr7MAttml0Zl3ONi73kjusEviQ6TiQeMyFNCyLt_XKy-iX000NiIqdrbNtNNCCZuVTYfARc8NLwFGfiz75tp7KLrgFpO2RK8VpcS9fchl9OEA_tMGzdypy_P2PHcAoGdp4-HUXRKeIBRiJ30TB7EqFypSp_PUqmLLQhnk3NsWa7TJYT3QaMXDBWPeZSRJnfHn_deWRoiP1oAA-BOfUz3E_F8HymVIiXT6XY4Fu2nZ7ZcBymreiIXmQz_ZySf-oyLBQdkZChYdjheyol7zX9n_jTGHKXZib7NSZcvDg3V2eul6qJdSZNRGVPE5gfyBDDXbTUe6UQQaOxQkaJVFJnkFX7MI_vv7fpw0GJTtX24y3OVptOuvr2ovkaglHFGXLT9CvEbjioCEROalK4C29EKZAgo9iWHCAre9xHYSfIfZ8_vZ4-xWHHECwYEBtW_7gkzXU0jXq6EKJ9TTFzekMoLK_"
#define REFRESH_TOKEN_URI "https://alexa.boeckling.net/auth/refresh/" REFRESH_TOKEN


typedef struct {
    char *buf;
    size_t len;
} buffer_t;

int auth_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data)
{
    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    // grow the buffer
    // If the ptr argument is NULL, realloc acts like malloc()
    buffer->buf = realloc(buffer->buf, buffer->len + len);

    if(buffer->buf == NULL) {
        // TODO: insufficient memory for reallocation
        return -1;
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
    http2_session_data_t *session_data = user_data;
    alexa_session_t *alexa_session = session_data->session_user_data;

    buffer_t *buffer = nghttp2_session_get_stream_user_data(session, stream_id);

    buffer->buf = realloc(buffer->buf, buffer->len + 1);
    buffer->buf[buffer->len] = '\0';

    cJSON *root = cJSON_Parse(buffer->buf);
    cJSON *token_item = cJSON_GetObjectItem(root, "access_token");
    char *access_token = token_item->valuestring;

    set_auth_token(alexa_session, access_token);

    cJSON_Delete(root);
    free(buffer->buf);
    free(buffer);

    nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);

    // xEventGroupSetBits(alexa_session->event_group, AUTH_TOKEN_VALID_BIT);

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

    ret = read_write_loop(http2_session_auth->nghttp2_session, http2_session_auth->ssl_session->ssl_context);
    ESP_LOGI(TAG, "auth_token_refresh event loop finished with %d", ret);
    free_http2_session_data(http2_session_auth, ret);

    // xTaskCreatePinnedToCore(&event_loop_task, "event_loop_task_auth", 8192, http2_session_auth, 1, NULL, 0);
}
