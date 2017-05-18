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
#include "alexa_messages.h"

/*
 {
    "header": {
        "namespace": "Alerts",
        "name": "AlertsState"
    },
    "payload": {
        "allAlerts": [
                          {
                "token": "{{STRING}}",
                "type": "{{STRING}}",
                "scheduledTime": "{{STRING}}"
            }
        ],
        "activeAlerts": [
                          {
                "token": "{{STRING}}",
                "type": "{{STRING}}",
                "scheduledTime": "{{STRING}}"
            }
        ]
    }
}
 */
static cJSON* ctx_alerts_state()
{
    cJSON *root, *header, *payload;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "Alerts");
    cJSON_AddStringToObject(header, "name", "AlertsState");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddItemToObject(payload, "allAlerts", cJSON_CreateArray());
    cJSON_AddItemToObject(payload, "activeAlerts", cJSON_CreateArray());

    return root;
}

/*
{
    "header": {
        "namespace": "AudioPlayer",
        "name": "PlaybackState"
    },
    "payload": {
        "token": "{{STRING}}",
        "offsetInMilliseconds": {{LONG}},
        "playerActivity": "{{STRING}}"
    }
}
*/
static cJSON* ctx_playback_state()
{
    cJSON *root, *header, *payload;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "AudioPlayer");
    cJSON_AddStringToObject(header, "name", "PlaybackState");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddStringToObject(payload, "token", "");
    cJSON_AddNumberToObject(payload, "offsetInMilliseconds", 0);
    cJSON_AddStringToObject(payload, "playerActivity", "IDLE");

    return root;
}

/*
 {
    "header": {
        "namespace": "Speaker",
        "name": "VolumeState"
    },
    "payload": {
        "volume": {{LONG}},
        "muted": {{BOOLEAN}}
    }
}
*/
static cJSON* ctx_volume_state()
{
    cJSON *root, *header, *payload;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "Speaker");
    cJSON_AddStringToObject(header, "name", "VolumeState");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddNumberToObject(payload, "volume", 100);
    cJSON_AddBoolToObject(payload, "muted", false);

    return root;
}

/*
{
    "header": {
        "namespace": "SpeechSynthesizer",
        "name": "SpeechState"
    },
    "payload": {
        "token": "{{STRING}}",
        "offsetInMilliseconds": {{LONG}},
        "playerActivity": "{{STRING}}"
    }
}
 */
static cJSON* ctx_speech_synth_state()
{
    cJSON *root, *header, *payload;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "SpeechSynthesizer");
    cJSON_AddStringToObject(header, "name", "SpeechState");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddStringToObject(payload, "token", "");
    cJSON_AddNumberToObject(payload, "offsetInMilliseconds", 0);
    cJSON_AddStringToObject(payload, "playerActivity", "FINISHED");

    return root;
}

/*
 {
    "header": {
        "namespace": "SpeechRecognizer",
        "name": "RecognizerState"
    },
    "payload": {
        "wakeword": "ALEXA"
    }
}
 */
static cJSON* ctx_speech_recognizer_state()
{
    cJSON *root, *header, *payload;

    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "header", header = cJSON_CreateObject());
    cJSON_AddStringToObject(header, "namespace", "SpeechRecognizer");
    cJSON_AddStringToObject(header, "name", "RecognizerState");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddStringToObject(payload, "wakeword", "ALEXA");

    return root;
}

static uint16_t msg_id = 1;
static uint16_t dialog_req_id = 1;
static char msg_id_buf[6];
static char dialog_req_id_buf[6];

/*
    {
      "context": [],
      "event": {}
    }
 */
char* create_evt_recognize()
{
    cJSON *root, *context, *event, *header, *payload, *context_obj, *initiator;
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
    snprintf(msg_id_buf, sizeof(msg_id_buf), "%u", msg_id++);
    cJSON_AddStringToObject(header, "messageId", msg_id_buf);
    snprintf(dialog_req_id_buf, sizeof(dialog_req_id_buf), "%u", dialog_req_id++);
    cJSON_AddStringToObject(header, "dialogRequestId", dialog_req_id_buf);


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
