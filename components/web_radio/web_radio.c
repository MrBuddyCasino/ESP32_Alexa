/*
 * web_radio.c
 *
 *  Created on: 13.03.2017
 *      Author: michaelboeckling
 */


#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "web_radio.h"
#include "http.h"
#define TAG "web_radio"


static void http_get_task(void *pvParameters)
{
    web_radio_t *radio_conf = pvParameters;

    // TODO: url parsing

    esp_err_t result = http_client_get(
            radio_conf->host,
            radio_conf->port,
            radio_conf->path,
            stream_reader,
            radio_conf->player_config);

    if(result != 0) {
        ESP_LOGE(TAG, "http_client_get error");
    } else {
        ESP_LOGI(TAG, "http_client_get completed");
    }
    // ESP_LOGI(TAG, "http_client_get stack: %d\n", uxTaskGetStackHighWaterMark(NULL));

    vTaskDelete(NULL);
}


void web_radio_init(web_radio_t *config) {

    config->player_config->state = PLAYING;

    // start http reader task
    xTaskCreatePinnedToCore(&http_get_task, "http_get_task", 2048, config, 20, NULL, 0);
}
