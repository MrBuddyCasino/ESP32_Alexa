/*
 * alexa_events_send.h
 *
 *  Created on: 16.06.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ALEXA_EVENTS_SEND_H_
#define _INCLUDE_ALEXA_EVENTS_SEND_H_

int event_send_state(alexa_session_t *alexa_session);
int event_send_settings_updated(alexa_session_t *alexa_session);

#endif /* _INCLUDE_ALEXA_EVENTS_SEND_H_ */
