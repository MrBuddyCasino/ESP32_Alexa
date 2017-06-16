/*
 * msg_events_settings.c
 *
 *  Created on: 16.06.2017
 *      Author: michaelboeckling
 */

#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "cJSON.h"

#include "common_buffer.h"
#include "multipart_producer.h"

/*
{
    “event": {
        "header": {
            "namespace": "Settings",
            "name": "SettingsUpdated",
            "messageId": "{{STRING}}"
        },
        "payload": {
            "settings": [
                {
                    "key": "{{STRING}}",
                    "value": "{{STRING}}"
                }
            ]
        }
    }
}
*/
char *create_evt_updt_settings(uint16_t msg_id, char *locale)
{
    cJSON *root, *event, *header, *settings, *payload, *keyval;

    char fmt_buf[6];
    root = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "event", event = cJSON_CreateObject());

    cJSON_AddItemToObject(event, "header", header = cJSON_CreateObject());

    cJSON_AddStringToObject(header, "namespace", "Settings");
    cJSON_AddStringToObject(header, "name", "SettingsUpdated");
    snprintf(fmt_buf, sizeof(fmt_buf), "%u", msg_id++);
    cJSON_AddStringToObject(header, "messageId", fmt_buf);

    cJSON_AddItemToObject(event, "payload", payload = cJSON_CreateObject());
    cJSON_AddItemToObject(payload, "settings", settings = cJSON_CreateArray());
    cJSON_AddItemToArray(settings, keyval = cJSON_CreateObject());
    cJSON_AddStringToObject(keyval, "key", "locale");
    cJSON_AddStringToObject(keyval, "value", locale);


    char *rendered = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return rendered;
}
