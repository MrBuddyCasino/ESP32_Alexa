/*
 * alexa.h
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ALEXA_H_
#define _INCLUDE_ALEXA_H_

/**
 * @struct
 *
 * The primary structure to hold the resources needed for an Alexa
 * session.  The details of this structure are intentionally hidden
 * from the public API.
 */
typedef struct alexa_session_struct_t alexa_session_t;

void set_auth_token(alexa_session_t *alexa_session, char* access_token);

void auth_token_refresh(alexa_session_t *alexa_session);

int alexa_init();

#endif /* _INCLUDE_ALEXA_H_ */
