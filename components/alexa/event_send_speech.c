/*
 * event_send_speech.c
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "freertos/freertos.h"
#include "esp_system.h"
#include "esp_log.h"

#include "nghttp2/nghttp2.h"

#include "../nghttp_client/include/nghttp2_client.h"
#include "multipart_parser.h"
#include "audio_player.h"
#include "alexa.h"
#include "audio_recorder.h"
#include "common_buffer.h"
#include "alexa_events.h"
#include "multipart_producer.h"

#define TAG "event_send_speech"


typedef enum {
    SPEECH_IDLE = 0, SPEECH_RECOGNIZING, SPEECH_BUSY, SPEECH_EXPECTING
} speech_recognizer_state_t;

static speech_recognizer_state_t state;

pcm_format_t buf_desc = {
    .sample_rate = 16000,
    .bit_depth = I2S_BITS_PER_SAMPLE_16BIT,
    .num_channels = 1,
    .buffer_format = PCM_LEFT_RIGHT
};

/* send data  */
static bool yield = false;
static uint16_t rounds = 0;
static uint32_t bytes_out_total = 0;
ssize_t send_speech_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data)
{

    // http2_session_data_t *session_data = user_data;
    // alexa_session_t *alexa_session = session_data->user_data;

    alexa_stream_t *alexa_stream = data_source->ptr;

    ssize_t bytes_written = 0;

    if(yield) {
        yield = false;
        // see https://github.com/nghttp2/nghttp2/pull/672/files#diff-20273fc5d9b0c6c133eb3d701444596d
        return NGHTTP2_ERR_PAUSE;
    }

    buffer_t *buffer = buf_wrap(buf, buf_length);

    switch (alexa_stream->next_action) {
        case META_HEADERS:
        case META_JSON:
            ; // fix C grammar oddity

            // write multipart headers
            //buf_write(buffer, JSON_PART_PREFIX, sizeof(JSON_PART_PREFIX) - 1);
            //size_t prefix_len = strlen(JSON_PART_PREFIX);
            //memcpy(buf, JSON_PART_PREFIX, prefix_len);
            begin_part_meta_data(buffer);

            // write json
            char *json = create_evt_recognize(alexa_stream->msg_id++, alexa_stream->dialog_req_id++);
            //size_t json_len = strlen(json);
            buf_write(buffer, json, strlen(json));
            //memcpy(buf + prefix_len, json, json_len);
            free(json);
            // bytes_written = prefix_len + json_len;
            bytes_written = buf_data_total(buffer);

            alexa_stream->next_action = AUDIO_HEADERS;
            break;

        case AUDIO_HEADERS:
            bytes_written = begin_part_audio_data(buffer);
            //bytes_written = strlen(AUDIO_PART_PREFIX);
            //memcpy(buf, AUDIO_PART_PREFIX, bytes_written);
            alexa_stream->next_action = AUDIO_DATA;
            // else won't print
            printf("%.*s\n", bytes_written, buf);
            // i2s_start(I2S_NUM_1);
            break;

        case AUDIO_DATA:
            ; // C grammar workaround

            /*
            // read audio from a file
            if(alexa_stream->file_pos == 0)
                alexa_stream->file_pos = file_start;

            uint8_t *pos = alexa_stream->file_pos;
            // size_t file_size = file_end - file_start;
            size_t remaining = file_end - pos;
            bytes_written = buf_length < remaining ? buf_length : remaining;
            memcpy(buf, pos, bytes_written);

            // ESP_LOGE(TAG, "AUDIO_DATA    buf_length: %d, remaining: %d", buf_length, remaining);
            if(buf_length > remaining) {
                alexa_stream->next_action = DONE;
            }

            yield = true;
            alexa_stream->file_pos += bytes_written;
            */



            /* Alexa wants:
             * 16bit Linear PCM
             * 16kHz sample rate
             * Single channel
             * Little endian byte order
             */

            // Amazon recommends 10ms of captured audio per chunk (320 bytes)
            uint8_t *buf_ptr_read = buf;
            uint8_t *buf_ptr_write = buf;

            // read whole block of samples
            int bytes_read = 0;
            while(bytes_read == 0) {
                bytes_read = i2s_read_bytes(I2S_NUM_1, (char*) buf, buf_length, 0);
            }

            //  convert 2x 32 bit stereo -> 1 x 16 bit mono
            uint32_t samples_read = bytes_read / 2 / (I2S_BITS_PER_SAMPLE_32BIT / 8);

            for(int i = 0; i < samples_read; i++) {
                buf_ptr_write[0] = buf_ptr_read[2]; // mid
                buf_ptr_write[1] = buf_ptr_read[3]; // high

                buf_ptr_write += 1 * (I2S_BITS_PER_SAMPLE_16BIT / 8);
                buf_ptr_read += 2 * (I2S_BITS_PER_SAMPLE_32BIT / 8);
            }
            bytes_written = samples_read * (I2S_BITS_PER_SAMPLE_16BIT / 8);

            // local echo
            render_samples((char*) buf, bytes_written, &buf_desc);

            rounds++;
            if(rounds > 1) {
                rounds = 0;
                yield = true;
            }

            bytes_out_total += bytes_written;
            //printf("bytes_out_total: %d\n", bytes_out_total);
            printf("bytes_out: %d\n", bytes_written);

            break;

        case DONE:
            audio_recorder_stop();
            renderer_stop();
            ESP_LOGE(TAG, "DONE");
            //bytes_written = strlen(BOUNDARY_EOF);
            //memcpy(buf, BOUNDARY_EOF, bytes_written);
            multipart_end(buffer);
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            bytes_out_total = 0;

            // reset state
            alexa_stream->next_action = META_HEADERS;
            break;
    }

    // null-terminate the buffer
    // buf[bytes_written] = 0;

    // printf("writing %d bytes to stream_id: %d, buf length: %d\n", bytes_written, stream_id, buf_length);

    // printf("%d bytes out\n", bytes_written);
    if(alexa_stream->next_action != AUDIO_DATA) {
        printf("%.*s\n", bytes_written, buf);
    }

    buf_destroy(buffer);

    return bytes_written;
}


void speech_recognizer_start_capture(alexa_session_t *alexa_session)
{
    state = SPEECH_RECOGNIZING;
    renderer_start();
    audio_recorder_start();

    alexa_stream_t *stream_events = get_stream_events(alexa_session);
    stream_events->next_action = META_HEADERS;
    stream_events->file_pos = 0;
    stream_events->current_part = META_HEADERS;

    net_send_event(alexa_session, send_speech_read_callback);
}

void speech_recognizer_stop_capture(alexa_session_t *alexa_session)
{
    state = SPEECH_BUSY;
    alexa_stream_t *stream_events = get_stream_events(alexa_session);
    stream_events->next_action = DONE;
}

