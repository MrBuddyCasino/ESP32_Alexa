/*
 * alexa.h
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ALEXA_H_
#define _INCLUDE_ALEXA_H_

#define ALEXA_ENDPOINT CONFIG_ALEXA_ENDPOINT
#define ALEXA_LOCALE CONFIG_ALEXA_LOCALE

/**
 * @struct
 *
 * The primary structure to hold the resources needed for an Alexa
 * session.  The details of this structure are intentionally hidden
 * from the public API.
 */
typedef struct alexa_session_struct_t alexa_session_t;

void *get_event_group(alexa_session_t *alexa_session);

void *get_io_context(alexa_session_t *alexa_session);

void set_auth_token(alexa_session_t *alexa_session, char* access_token);

void auth_token_refresh(alexa_session_t *alexa_session);

int alexa_send_event(alexa_session_t *alexa_session, nghttp2_data_source_read_callback read_callback);

int alexa_send_ping(alexa_session_t *alexa_session, nghttp2_data_source_read_callback read_callback);

extern const int AUTH_TOKEN_VALID_BIT;
extern const int DOWNCHAN_CONNECTED_BIT;

typedef enum {
    CONN_CONNECTING, CONN_UNAUTHORIZED, CONN_OPEN, CONN_CLOSED
} alexa_stream_status_t;

typedef enum
{
    META_HEADERS, META_JSON, AUDIO_HEADERS, AUDIO_DATA, DONE
} part_type_t;

typedef enum {
    STREAM_DIRECTIVES, STREAM_EVENTS, STREAM_PING
} stream_type_t ;

typedef struct
{
    stream_type_t stream_type;
    alexa_session_t *alexa_session;
    http2_session_data_t *http2_session;
    int32_t stream_id;
    alexa_stream_status_t status;
    multipart_parser* m_parser;
    char *boundary;
    part_type_t current_part;
    part_type_t next_action;
    uint8_t *file_pos;
    uint16_t msg_id;
    uint16_t dialog_req_id;
} alexa_stream_t;


player_t *get_player_config(alexa_session_t *alexa_session);

alexa_stream_t *get_stream_events(alexa_session_t *alexa_session);

alexa_stream_t *get_stream_directives(alexa_session_t *alexa_session);

#endif /* _INCLUDE_ALEXA_H_ */
