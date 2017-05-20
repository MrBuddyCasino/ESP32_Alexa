/*
 * alexa_messages.h
 *
 *  Created on: 16.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ALEXA_MESSAGES_H_
#define _INCLUDE_ALEXA_MESSAGES_H_

/* System.SynchronizeState */
char *create_evt_sync_state(uint16_t msg_id);

/* SpeechRecognizer.Recognize */
char *create_evt_recognize(uint16_t msg_id, uint16_t dialog_req_id);

#endif /* _INCLUDE_ALEXA_MESSAGES_H_ */
