/*
 * json_proto.c
 *
 *  Created on: 16.05.2017
 *      Author: michaelboeckling
 */

#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"

#include "alexa_events.h"
#include "include/alexa_events_context.h"

/*
{
  "context": [
    {{Alerts.AlertsState}},
    {{AudioPlayer.PlaybackState}},
    {{Speaker.VolumeState}},
    {{SpeechSynthesizer.SpeechState}},
    {{SpeechRecognizer.RecognizerState}}
  ],
  "event": {
    "header": {
      "namespace": "SpeechRecognizer",
      "name": "Recognize",
      "messageId": "{{STRING}}",
      "dialogRequestId": "{{STRING}}"
    },
    "payload": {
      "profile": "{{STRING}}",
      "format": "{{STRING}}",
      "initiator": {
        "type": "{{STRING}}"
      }
    }
  }
}
 */
char* create_evt_recognize(uint16_t msg_id, uint16_t dialog_req_id)
{
    cJSON *root, *context, *event, *header, *payload, *initiator;

    //printbuffer pb = {};
    //print_value(root, 0, 0, pb);
    char fmt_buf[6];

    root = cJSON_CreateObject();

    /* context: component states */
    cJSON_AddItemToObject(root, "context", context = cJSON_CreateArray());
    cJSON_AddItemToArray(context, ctx_alerts_state());
    cJSON_AddItemToArray(context, ctx_playback_state());
    cJSON_AddItemToArray(context, ctx_volume_state());
    cJSON_AddItemToArray(context, ctx_speech_synth_state());
    cJSON_AddItemToArray(context, ctx_speech_recognizer_state());


    /*
     * "event":{
     */
    cJSON_AddItemToObject(root, "event", event = cJSON_CreateObject());

    /*
     "header": {
        "namespace": "SpeechRecognizer",
        "name": "Recognize",
        "messageId": "{{STRING}}",
        "dialogRequestId": "{{STRING}}"
    }
     */
    cJSON_AddItemToObject(event, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "SpeechRecognizer");
    cJSON_AddStringToObject(header, "name", "Recognize");
    snprintf(fmt_buf, sizeof(fmt_buf), "%u", msg_id++);
    cJSON_AddStringToObject(header, "messageId", fmt_buf);
    snprintf(fmt_buf, sizeof(fmt_buf), "%u", dialog_req_id++);
    cJSON_AddStringToObject(header, "dialogRequestId", fmt_buf);


    /*
     "payload": {
      "profile": "{{STRING}}",
      "format": "{{STRING}}",
      "initiator": {
        "type": "{{STRING}}",
        "payload": {
          "wakeWordIndices": {
            "startIndexInSamples": {{LONG}},
            "endIndexInSamples": {{LONG}}
          }
        }
      }
    }
    */
    cJSON_AddItemToObject(event, "payload", payload = cJSON_CreateObject());
    // cJSON_AddStringToObject(payload, "profile", "CLOSE_TALK");
    cJSON_AddStringToObject(payload, "profile", "NEAR_FIELD");
    cJSON_AddStringToObject(payload, "format",
            "AUDIO_L16_RATE_16000_CHANNELS_1");

    cJSON_AddItemToObject(payload, "initiator", initiator = cJSON_CreateObject());
    cJSON_AddStringToObject(initiator, "type", "TAP");

    // char *rendered = cJSON_Print(root);
    char *rendered = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    return rendered;
}
