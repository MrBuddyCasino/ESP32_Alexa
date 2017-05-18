/*
 * directive_handler.c
 *
 *  Created on: 16.05.2017
 *      Author: michaelboeckling
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "cJSON.h"

#include "web_radio.h"
#include "directive_handler.h"

#define TAG "directive_handler"

void handle_speak_directive(cJSON *directive)
{

}

static void start_web_radio(char *play_url)
{
    // init web radio
    web_radio_t *radio_config = calloc(1, sizeof(web_radio_t));
    radio_config->url = play_url;

    // init player config
    radio_config->player_config = calloc(1, sizeof(player_t));
    radio_config->player_config->command = CMD_NONE;
    radio_config->player_config->decoder_status = UNINITIALIZED;
    radio_config->player_config->decoder_command = CMD_NONE;
    radio_config->player_config->buffer_pref = BUF_PREF_SAFE;
    radio_config->player_config->media_stream = calloc(1, sizeof(media_stream_t));

    // init renderer
    // renderer_init(create_renderer_config());

    // start radio
    web_radio_init(radio_config);
    web_radio_start(radio_config);
}

void handle_play_directive(cJSON *directive)
{
    cJSON *payload = cJSON_GetObjectItem(directive, "payload");
    cJSON *audioItem = cJSON_GetObjectItem(payload, "audioItem");
    cJSON *stream = cJSON_GetObjectItem(audioItem, "stream");
    cJSON *url = cJSON_GetObjectItem(stream, "url");

    ESP_LOGI(TAG, "playing url %s", url->valuestring);
    start_web_radio(strdup(url->valuestring));
}

void handle_directive(const char *at, size_t length)
{
    printf("handle_directive:\n%.*s\n", length, at);

    cJSON *root = cJSON_Parse(at);

    cJSON *directive = cJSON_GetObjectItem(root, "directive");
    cJSON *header = cJSON_GetObjectItem(directive, "header");
    cJSON *name = cJSON_GetObjectItem(header, "name");

    if(strstr(name->valuestring, "Speak"))
    {
        handle_speak_directive(directive);
    }

    if(strstr(name->valuestring, "Play"))
    {
        handle_play_directive(directive);
    }

    cJSON_Delete(root);
}
