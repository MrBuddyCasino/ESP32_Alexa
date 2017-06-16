/*
 * system_events.c
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"

#include "common_buffer.h"
#include "alexa_events_context.h"
#include "multipart_producer.h"

/**
 {
    "context": [
        {{Alerts.AlertsState}},
        {{AudioPlayer.PlaybackState}},
        {{Speaker.VolumeState}},
        {{SpeechSynthesizer.SpeechState}}
        {{SpeechRecognizer.RecognizerState}}
    ],
    "event": {
        "header": {
            "namespace": "System",
            "name": "SynchronizeState",
            "messageId": "{{STRING}}"
        },
        "payload": {
        }
    }
}
 */
char *create_evt_sync_state(uint16_t msg_id)
{
    cJSON *root, *event, *header;

    char fmt_buf[6];
    root = cJSON_CreateObject();

    /* context: component states */
    cJSON_AddItemToObject(root, "context", ctx_all_states());

    cJSON_AddItemToObject(root, "event", event = cJSON_CreateObject());

    cJSON_AddItemToObject(event, "header", header = cJSON_CreateObject());

    cJSON_AddStringToObject(header, "namespace", "System");
    cJSON_AddStringToObject(header, "name", "SynchronizeState");
    snprintf(fmt_buf, sizeof(fmt_buf), "%u", msg_id++);
    cJSON_AddStringToObject(header, "messageId", fmt_buf);

    cJSON_AddItemToObject(event, "payload", cJSON_CreateObject());

    char *rendered = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return rendered;
}
