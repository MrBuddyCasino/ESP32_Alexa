/*
 * event_send_speech.h
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_EVENT_SEND_SPEECH_H_
#define _INCLUDE_EVENT_SEND_SPEECH_H_

void speech_recognizer_start_capture(alexa_session_t *alexa_session);

void speech_recognizer_stop_capture(alexa_session_t *alexa_session);


ssize_t send_speech_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data);

typedef enum {
    SPEECH_IDLE = 0, SPEECH_RECOGNIZING, SPEECH_BUSY, SPEECH_EXPECTING
} speech_recognizer_state_t;

bool speech_recognizer_is_ready();
void speech_recognizer_set_state(speech_recognizer_state_t new_state);

#endif /*_INCLUDE_EVENT_SEND_SPEECH_H_ */
