/*
 * audio_recorder.c
 *
 *  Created on: 30.03.2017
 *      Author: michaelboeckling
 */

#include <stdlib.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "driver/gpio.h"
#include "driver/i2s.h"

void audio_recorder_init()
{
	i2s_config_t i2s_config = {
			.mode = I2S_MODE_MASTER | I2S_MODE_RX,
			.sample_rate = 44100,
			.bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT,
			.channel_format = I2S_CHANNEL_FMT_RIGHT_LEFT,
			.communication_format = I2S_COMM_FORMAT_I2S | I2S_COMM_FORMAT_I2S_MSB,
			.dma_buf_count = 14,                            // number of buffers, 128 max.
			.dma_buf_len = 32 * 2,                          // size of each buffer
			.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1        // Interrupt level 1
	};

    i2s_pin_config_t pin_config = {
            .bck_io_num = GPIO_NUM_16,
            .ws_io_num = GPIO_NUM_17,
            .data_out_num = I2S_PIN_NO_CHANGE,
            .data_in_num = GPIO_NUM_18
    };

    i2s_driver_install(I2S_NUM_1, &i2s_config, 0, NULL);
    i2s_set_pin(I2S_NUM_1, &pin_config);
}

void audio_recorder_start()
{
    i2s_start(I2S_NUM_1);
}

void audio_recorder_stop()
{
    i2s_stop(I2S_NUM_1);
}

