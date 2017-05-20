/*
 * events_context.c
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"

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
cJSON* ctx_alerts_state()
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
cJSON* ctx_playback_state()
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
cJSON* ctx_volume_state()
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
cJSON* ctx_speech_synth_state()
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
cJSON* ctx_speech_recognizer_state()
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

cJSON *ctx_all_states()
{
    cJSON *context = cJSON_CreateArray();

    cJSON_AddItemToArray(context, ctx_alerts_state());
    cJSON_AddItemToArray(context, ctx_playback_state());
    cJSON_AddItemToArray(context, ctx_volume_state());
    cJSON_AddItemToArray(context, ctx_speech_synth_state());
    cJSON_AddItemToArray(context, ctx_speech_recognizer_state());

    return context;
}
