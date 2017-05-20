/*
 * events_context.h
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_EVENTS_CONTEXT_H_
#define _INCLUDE_EVENTS_CONTEXT_H_

cJSON* ctx_alerts_state();
cJSON* ctx_playback_state();
cJSON* ctx_volume_state();
cJSON* ctx_speech_synth_state();
cJSON* ctx_speech_recognizer_state();

cJSON *ctx_all_states();

#endif /* _INCLUDE_EVENTS_CONTEXT_H_ */
