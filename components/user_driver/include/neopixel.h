#pragma once

#include <driver/gpio.h>
#include <driver/rmt.h>

typedef struct pixel {
	uint8_t red;
	uint8_t green;
	uint8_t blue;
	uint8_t white;
} pixel_t;

typedef struct pixel_settings {
	pixel_t * pixels;
	rmt_item32_t * items;
	uint16_t pixel_count;
	uint8_t brightness;
	char color_order[5];
	uint8_t red_offset;
	uint8_t blue_offset;
	uint8_t green_offset;
	uint8_t white_offset;
} pixel_settings_t;

#define NEOPIXEL_INIT_CONFIG_DEFAULT() {\
	.brightness = 255,\
	.color_order = "BRGW",\
	.red_offset = 24,\
	.green_offset = 16,\
	.blue_offset = 8,\
	.white_offset = 0\
};

#define NEOPIXEL_RMT_INIT_CONFIG_DEFAULT(x, y) {\
	.rmt_mode = RMT_MODE_TX,\
	.channel = RMT_CHANNEL_##y,\
	.gpio_num = x,\
	.mem_block_num = 8 - RMT_CHANNEL_##y,\
	.clk_div = 8,\
	.tx_config.loop_en = 0,\
	.tx_config.carrier_en = 0,\
	.tx_config.idle_output_en = 1,\
	.tx_config.idle_level = (rmt_idle_level_t)0,\
	.tx_config.carrier_freq_hz = 10000,\
	.tx_config.carrier_level = (rmt_carrier_level_t)1,\
	.tx_config.carrier_duty_percent = 50\
};

typedef uint8_t pixel_order_t;

void np_set_color_order(pixel_settings_t *px, pixel_order_t order);
void np_set_pixel_color(pixel_settings_t *px, uint16_t idx, uint8_t red, uint8_t green, uint8_t blue, uint8_t white);
void np_set_brightness(pixel_settings_t *px, uint8_t level);
void np_show(pixel_settings_t *px);
void np_clear(pixel_settings_t *px);

float* rgb_to_hsb(uint8_t, uint8_t, uint8_t, float*);
uint32_t hsb_to_rgb(float hue, float saturation, float brightness);
