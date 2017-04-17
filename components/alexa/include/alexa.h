/*
 * alexa.h
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#ifndef COMPONENTS_ALEXA_INCLUDE_ALEXA_H_
#define COMPONENTS_ALEXA_INCLUDE_ALEXA_H_

typedef enum {
    CONN_CONNECTING, CONN_UNAUTHORIZED, CONN_OPEN, CONN_CLOSED
} alexa_stream_status_t;

typedef struct
{
    int32_t stream_id;
    alexa_stream_status_t status;
} alexa_stream_t;

typedef struct
{
    player_t *player_config;
    char *auth_token;
    EventGroupHandle_t event_group;
    alexa_stream_t *downchannel;
} alexa_session_t;


int alexa_init();

alexa_session_t *get_alexa_session();

#endif /* COMPONENTS_ALEXA_INCLUDE_ALEXA_H_ */
