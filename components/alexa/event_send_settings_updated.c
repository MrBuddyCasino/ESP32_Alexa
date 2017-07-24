/*
 * event_settings_updated.c
 *
 *  Created on: 16.06.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "esp_system.h"
#include "esp_log.h"

#include "nghttp2/nghttp2.h"
#include "nghttp2_client.h"
#include "multipart_parser.h"
#include "audio_player.h"
#include "alexa.h"
#include "audio_recorder.h"
#include "common_buffer.h"
#include "include/alexa_events_js.h"
#include "include/alexa_events_js.h"
#include "multipart_producer.h"

#define TAG "event_settings"


ssize_t settings_updated_read_cb(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{
    alexa_stream_t *alexa_stream = data_source->ptr;

    buffer_t *buffer = buf_wrap(buf, buf_length);

    begin_part_meta_data(buffer);


    char *json = create_evt_updt_settings(alexa_stream->msg_id++, ALEXA_LOCALE);
    buf_write(buffer, json, strlen(json));
    free(json);

    multipart_end(buffer);
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    ssize_t bytes_written = buf_data_total(buffer);
    printf("%.*s\n", bytes_written, buf);
    buf_destroy(buffer);

    return bytes_written;
}


int event_send_settings_updated(alexa_session_t *alexa_session)
{
    return alexa_send_event(alexa_session, settings_updated_read_cb);
}
