#include <driver/gpio.h>
#include <driver/rmt.h>
#include <esp_log.h>
#include <math.h>

#include "neopixel.h"

static const char tag[] = "neopixel";

/**
 * Set two levels of RMT output to the Neopixel value for a "1".
 * This is:
 *  * a logic 1 for 0.7us
 *  * a logic 0 for 0.6us
 */
static void neopixel_mark(rmt_item32_t *pItem) {
	assert(pItem != NULL);
	pItem->level0    = 1;
	pItem->duration0 = 10;
	pItem->level1    = 0;
	pItem->duration1 = 6;
}

/**
 * Set two levels of RMT output to the Neopixel value for a "0".
 * This is:
 *  * a logic 1 for 0.35us
 *  * a logic 0 for 0.8us
 */
static void neopixel_space(rmt_item32_t *pItem) {
	assert(pItem != NULL);
	pItem->level0    = 1;
	pItem->duration0 = 4;
	pItem->level1    = 0;
	pItem->duration1 = 8;
}

static void rmt_terminate(rmt_item32_t *pItem) {
	assert(pItem != NULL);
	pItem->level0    = 0;
	pItem->duration0 = 0;
	pItem->level1    = 0;
	pItem->duration1 = 0;
}

uint8_t offset_color(char o, pixel_t *p) {
	switch(o) {
		case 'R': return p->red;
		case 'B': return p->green;
		case 'G': return p->blue;
		case 'W': return p->white;
	}

	ESP_LOGE(tag, "Unknown color channel 0x%2x", o);
	return 0;
}

uint32_t get_wire_value(pixel_settings_t *px, uint16_t pixel) {
	return  (offset_color(px->color_order[0], &px->pixels[pixel]) << 24) |
		(offset_color(px->color_order[1], &px->pixels[pixel]) << 16) |
		(offset_color(px->color_order[2], &px->pixels[pixel]) << 8)  |
		(offset_color(px->color_order[3], &px->pixels[pixel]));
}

void np_set_color_order(pixel_settings_t *px, pixel_order_t order)
{
	assert(px != NULL);
	px->white_offset = (order >> 6) & 0b11;
	px->red_offset   = (order >> 4) & 0b11;
	px->green_offset = (order >> 2) & 0b11;
	px->blue_offset  = order & 0b11;
}

void np_set_pixel_color(pixel_settings_t *px, uint16_t idx, uint8_t red, uint8_t green, uint8_t blue, uint8_t white)
{
	assert(px != NULL);
	assert(px->pixels != NULL);
	assert(idx < px->pixel_count);

	px->pixels[idx].red   = red;
	px->pixels[idx].green = green;
	px->pixels[idx].blue  = blue;
	px->pixels[idx].white = white;
}

void np_set_brightness(pixel_settings_t *px, uint8_t level)
{
}

void np_show(pixel_settings_t *px)
{
  rmt_item32_t * pCurrentItem = px->items;

  for (uint16_t i = 0; i < px->pixel_count; i++) {
    uint32_t p = get_wire_value(px, i);

    for (int j=31; j>=0; j--) {
      // 32 bits of data represent the red, green, blue and white channels. The
      // value of the 32 bits to output is in the variable p. This value must
      // be written to the RMT subsystem in big-endian format. Iterate through
      // the pixels MSB to LSB
      if (p & (1<<j)) {
        neopixel_mark(pCurrentItem);
      } else {
        neopixel_space(pCurrentItem);
      }
      pCurrentItem++;
    }
  }

  rmt_terminate(pCurrentItem);

  ESP_ERROR_CHECK(rmt_write_items(RMT_CHANNEL_0, px->items, px->pixel_count * 32, 1));
}

void np_clear(pixel_settings_t *px)
{
	for(size_t i = 0; i < px->pixel_count; ++i) {
		np_set_pixel_color(px, i, 0, 0, 0, 0);
	}
}

float *rgb_to_hsb(uint8_t r, uint8_t g, uint8_t b, float *hsb) {
	float hue, sat, brt;

	if (hsb == NULL) {
		return NULL;
	}

	int cmax = (r > g) ? r : g;
	if(b > cmax) cmax = b;
	int cmin = (r < g) ? r : g;
	if(b < cmin) cmin = b;

	brt = ((float) cmax) / 255.0f;

	if(cmax != 0) {
		sat = ((float) (cmax - cmin)) / ((float) cmax);
	} else {
		sat = 0;
	}

	if(sat == 0) {
		hue = 0;
	} else {
		float redc = ((float) (cmax - r)) / ((float) (cmax - cmin));
		float greenc = ((float) (cmax - g)) / ((float) (cmax - cmin));
		float bluec = ((float) (cmax - b)) / ((float) (cmax - cmin));

		if(r == cmax) {
			hue = bluec - greenc;
		} else if(g == cmax) {
			hue = 2.0f + redc - bluec;
		} else {
			hue = 4.0f + greenc - redc;
		}

		hue = hue / 6.0f;

		if(hue < 0) hue = hue + 1.0f;
	}

	hsb[0] = hue;
	hsb[1] = sat;
	hsb[2] = brt;

	return hsb;
}

uint32_t hsb_to_rgb(float hue, float saturation, float brightness) {
	int r = 0, g = 0, b = 0;
	if (saturation == 0) {
		r = g = b = (int) (brightness * 255.0f + 0.5f);
	} else {
		float h = (hue - (float)floor(hue)) * 6.0f;
		float f = h - (float)floor(h);
		float p = brightness * (1.0f - saturation);
		float q = brightness * (1.0f - saturation * f);
		float t = brightness * (1.0f - (saturation * (1.0f - f)));

		switch ((int) h) {
			case 0:
				r = (int) (brightness * 255.0f + 0.5f);
				g = (int) (t * 255.0f + 0.5f);
				b = (int) (p * 255.0f + 0.5f);
				break;
			case 1:
				r = (int) (q * 255.0f + 0.5f);
				g = (int) (brightness * 255.0f + 0.5f);
				b = (int) (p * 255.0f + 0.5f);
				break;
			case 2:
				r = (int) (p * 255.0f + 0.5f);
				g = (int) (brightness * 255.0f + 0.5f);
				b = (int) (t * 255.0f + 0.5f);
				break;
			case 3:
				r = (int) (p * 255.0f + 0.5f);
				g = (int) (q * 255.0f + 0.5f);
				b = (int) (brightness * 255.0f + 0.5f);
				break;
			case 4:
				r = (int) (t * 255.0f + 0.5f);
				g = (int) (p * 255.0f + 0.5f);
				b = (int) (brightness * 255.0f + 0.5f);
				break;
			case 5:
				r = (int) (brightness * 255.0f + 0.5f);
				g = (int) (p * 255.0f + 0.5f);
				b = (int) (q * 255.0f + 0.5f);
				break;
		}
	}
	return 0xff000000 | (r << 16) | (g << 8) | (b << 0);
}
