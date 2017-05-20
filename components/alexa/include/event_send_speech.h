/*
 * event_send_speech.h
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_EVENT_SEND_SPEECH_H_
#define _INCLUDE_EVENT_SEND_SPEECH_H_

ssize_t send_speech_read_callback(nghttp2_session *session, int32_t stream_id,
        uint8_t *buf, size_t buf_length, uint32_t *data_flags,
        nghttp2_data_source *data_source, void *user_data);

#endif /*_INCLUDE_EVENT_SEND_SPEECH_H_ */
