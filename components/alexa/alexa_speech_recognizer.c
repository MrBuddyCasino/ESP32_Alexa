/*
 * event_send_speech.c
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "esp_system.h"
#include "esp_log.h"

#include "nghttp2/nghttp2.h"

#include "nghttp2_client.h"
#include "multipart_parser.h"
#include "audio_player.h"
#include "alexa.h"
#include "audio_recorder.h"
#include "common_buffer.h"
#include "multipart_producer.h"
#include "ui.h"
#include "alexa_speech_recognizer.h"

#include "include/alexa_events_js.h"

#define TAG "event_send_speech"


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
            begin_part_meta_data(buffer);

            // write json
            char *json = create_evt_recognize(alexa_stream->msg_id++, alexa_stream->dialog_req_id++);
            buf_write(buffer, json, strlen(json));
            free(json);
            bytes_written = buf_data_total(buffer);

            alexa_stream->next_action = AUDIO_HEADERS;
            break;

        case AUDIO_HEADERS:
            bytes_written = begin_part_audio_data(buffer);
            alexa_stream->next_action = AUDIO_DATA;
            // else won't print
            printf("%.*s\n", bytes_written, buf);
            break;

        case AUDIO_DATA:
            ;
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
            //render_samples((char*) buf, bytes_written, &buf_desc);

            rounds++;
            // TODO: test if if(rounds > 4) is better
             if(rounds > 1) {
                rounds = 0;
                yield = true;
            }

            bytes_out_total += bytes_written;
            printf("bytes_out: %d\n", bytes_written);

            break;

        case DONE:
            audio_recorder_stop();
            //renderer_stop();
            ESP_LOGE(TAG, "DONE");
            multipart_end(buffer);
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            bytes_out_total = 0;

            // reset state
            alexa_stream->next_action = META_HEADERS;
            break;
    }

    // printf("writing %d bytes to stream_id: %d, buf length: %d\n", bytes_written, stream_id, buf_length);

    // printf("%d bytes out\n", bytes_written);
    if(alexa_stream->next_action != AUDIO_DATA) {
        printf("%.*s\n", bytes_written, buf);
    }

    //buf_destroy(buffer);
    free(buffer);

    return bytes_written;
}


void speech_recognizer_start_capture(alexa_session_t *alexa_session)
{
    state = SPEECH_RECOGNIZING;
    //renderer_start();
    audio_recorder_start();

    alexa_stream_t *stream_events = get_stream_events(alexa_session);
    stream_events->next_action = META_HEADERS;
    stream_events->file_pos = 0;
    stream_events->current_part = META_HEADERS;

    alexa_send_event(alexa_session, send_speech_read_callback);
}

void speech_recognizer_stop_capture(alexa_session_t *alexa_session)
{
    //state = SPEECH_BUSY;
    state = SPEECH_IDLE;
    alexa_stream_t *stream_events = get_stream_events(alexa_session);
    stream_events->next_action = DONE;
    ui_queue_event(UI_NONE);
}

bool speech_recognizer_is_ready()
{
    return state == SPEECH_IDLE;
}

void speech_recognizer_set_state(speech_recognizer_state_t new_state)
{
    state = new_state;
}
