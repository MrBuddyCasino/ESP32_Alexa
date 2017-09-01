/*
 * asio_ui.c
 *
 *  Created on: 02.06.2017
 *      Author: michaelboeckling
 */

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <soc/rmt_struct.h>
#include <esp_system.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <driver/gpio.h>
#include "ws2812.h"
#include "neopixel.h"
#include "ui.h"
#include "url_parser.h"
#include "asio.h"

#define TAG "led_ui"


#define delay_ms(ms) ((ms) / portTICK_RATE_MS)

#define time_before(a, b) \
    ((a)->tv_sec < (b)->tv_sec || \
     ((a)->tv_sec == (b)->tv_sec && (a)->tv_usec < (b)->tv_usec))

#define time_sub(a, b, res) do { \
    (res)->sec = (a)->sec - (b)->sec; \
    (res)->usec = (a)->usec - (b)->usec; \
    if ((res)->usec < 0) { \
        (res)->sec--; \
        (res)->usec += 1000000; \
    } \
} while (0)


pixel_settings_t px = NEOPIXEL_INIT_CONFIG_DEFAULT();
pixel_t pixel = {
    .red = 0,
    .green = 0,
    .blue = 0,
    .white = 3
};


static uint32_t get_timestamp()
{
    // return xthal_get_ccount() / (CPU_CLK_FREQ_ROM / 1000);
    // return system_get_time();
    return xTaskGetTickCount() * (1000 / configTICK_RATE_HZ);
}


static rgbVal black =   {.r=0, .g=0, .b=0};
static rgbVal white =   {.r=255, .g=255, .b=255};
static rgbVal red =     {.r=32, .g=0, .b=0};
static rgbVal green =   {.r=0, .g=32, .b=0};
static rgbVal blue =    {.r=0, .g=0, .b=32};

typedef enum {
    PATTERN_ALTERNATE,
    PATTERN_SOLID // repeat for all LEDs in chain
} anim_frame_pattern_t;

typedef struct {
    uint32_t duration_ms;
    rgbVal color;
    anim_frame_pattern_t pattern;
} anim_frame_t;

typedef struct {
    uint8_t num_frames;
    anim_frame_t frames[];
} animation_t;


static animation_t ANIM_NONE = {
        .frames = {
                { .color = {.r=0, .g=0, .b=0}, .duration_ms = 0, .pattern = PATTERN_SOLID }
        },
        .num_frames = 2
};

static animation_t ANIM_BLINK_RED = {
        .frames = {
                { .color = {.r=255, .g=0, .b=0}, .duration_ms = 250, .pattern = PATTERN_ALTERNATE },
                { .color = {.r=255, .g=0, .b=0}, .duration_ms = 250, .pattern = PATTERN_ALTERNATE }
        },
        .num_frames = 2
};

static animation_t ANIM_BLINK_BLUE = {
        .frames = {
                { .color = {.r=0, .g=0, .b=255}, .duration_ms = 250, .pattern = PATTERN_ALTERNATE },
                { .color = {.r=0, .g=0, .b=255}, .duration_ms = 250, .pattern = PATTERN_ALTERNATE }
        },
        .num_frames = 2
};

typedef struct {
    gpio_num_t pin;
    uint16_t num_leds;
    QueueHandle_t ui_queue;
    animation_t *curr_anim;
    uint32_t timestamp;
    uint32_t switch_timestamp;
    int8_t curr_frame;
} led_ui_t;

/** UI object instance */
static led_ui_t *led_ui_obj;


static void calc_frame_switch_time()
{
    animation_t *curr_anim = led_ui_obj->curr_anim;
    if(curr_anim->frames[led_ui_obj->curr_frame].duration_ms == 0) {
        led_ui_obj->switch_timestamp = INT32_MAX;
    } else {
        led_ui_obj->switch_timestamp = led_ui_obj->timestamp + curr_anim->frames[led_ui_obj->curr_frame].duration_ms;
    }
}

static void render_frame()
{

    if(led_ui_obj->timestamp < led_ui_obj->switch_timestamp)
    {
        // nothing to do
        return;
    }
    else
    {
        // ESP_LOGW(TAG, "render frame - timestamp: %d, switch_timestamp: %d", led_ui_instance->timestamp, led_ui_instance->switch_timestamp);

        // end reached, rewind
        animation_t *curr_anim = led_ui_obj->curr_anim;
        if(led_ui_obj->curr_frame >= curr_anim->num_frames) {
            led_ui_obj->curr_frame = 0;
        }

        /*
        // change both at once
        rgbVal array[2] = {
                curr_anim->frames[led_ui_instance->curr_frame].color,
                curr_anim->frames[led_ui_instance->curr_frame].color
        };
        ws2812_setColors(2, array);
        */

        // alternating
        anim_frame_t frame = curr_anim->frames[led_ui_obj->curr_frame];
        rgbVal colors[led_ui_obj->num_leds];
        for(int i = 0; i < led_ui_obj->num_leds; i++)
        {
            if(((led_ui_obj->curr_frame + i) % 2 == 0) &&
                    (frame.pattern == PATTERN_ALTERNATE)) {
                //colors[i] = black;
                np_set_pixel_color(&px, i, 0, 0, 0, 0);
            } else {
                //colors[i] = frame.color;
                np_set_pixel_color(&px, i, frame.color.r, frame.color.g, frame.color.b, 0);
            }
        }
        ESP_LOGE(TAG, "setColors 0=%d, 1=%d", colors[0].num, colors[1].num);
        //ws2812_setColors(led_ui_obj->num_leds, colors);
        np_show(&px);

        calc_frame_switch_time();

        led_ui_obj->curr_frame++;
    }
}



/* this should probably use timers, sorry guys */
void led_ui_run()
{
    ui_event_t curr_evt = UI_NONE;

    // update current time
    led_ui_obj->timestamp = get_timestamp();

    // new event? -> new animation
    if(xQueueReceive((led_ui_obj->ui_queue), &curr_evt, 0))
    {
        ESP_LOGW(TAG, "switching anim");

        // select new anim
        switch(curr_evt)
        {
            case UI_NONE:
                led_ui_obj->curr_anim = &ANIM_NONE;
            break;

            case UI_CONNECTING:
                led_ui_obj->curr_anim = &ANIM_BLINK_RED;
            break;

            case UI_CONNECTED:
                led_ui_obj->curr_anim = &ANIM_NONE;
            break;

            case UI_RECOGNIZING_SPEECH:
                led_ui_obj->curr_anim = &ANIM_BLINK_RED;
            break;

            case UI_SYNTHESIZING_SPEECH:
                led_ui_obj->curr_anim = &ANIM_BLINK_BLUE;
            break;
        }

        // reset frame pos
        led_ui_obj->curr_frame = 0;
        led_ui_obj->switch_timestamp = 0;
    }

    render_frame();
}


void ui_queue_event(ui_event_t evt)
{
    if(led_ui_obj != NULL && led_ui_obj->ui_queue != NULL)
        xQueueSendToBackFromISR(led_ui_obj->ui_queue, &evt, 0);
        //xQueueSend(led_ui_instance.ui_queue, &evt, 0);
}

asio_result_t led_ui_init(gpio_num_t gpio_pin, uint16_t num_leds)
{
    led_ui_obj = (led_ui_t*) malloc(sizeof(led_ui_t));

    led_ui_obj->curr_anim = &ANIM_NONE;
    led_ui_obj->pin = gpio_pin;
    led_ui_obj->num_leds = num_leds;

    QueueHandle_t q = xQueueCreate(1, sizeof(ui_event_t));
    if(q == NULL) {
        ESP_LOGW(TAG, "no queue");
        return ASIO_ERR;
    }
    led_ui_obj->ui_queue = q;

    /*
    ws2812_init(gpio_pin, LED_WS2812B);
    //ws2812_setColors(2, &black);
    rgbVal colors[num_leds];
    memset(colors, 0, sizeof(rgbVal) * num_leds);
    ws2812_setColors(num_leds, colors);
    */
    px.pixel_count = num_leds;
    px.items = malloc(sizeof(rmt_item32_t) * ((px.pixel_count * 32) + 1));
    px.pixels = malloc(sizeof(pixel_t) * px.pixel_count);

    rmt_config_t rx = NEOPIXEL_RMT_INIT_CONFIG_DEFAULT(gpio_pin, 0);
    ESP_ERROR_CHECK(rmt_config(&rx));
    ESP_ERROR_CHECK(rmt_driver_install(RMT_CHANNEL_0, 0, 0));
    ESP_ERROR_CHECK(rmt_set_pin(RMT_CHANNEL_0, RMT_MODE_TX, gpio_pin));

    np_clear(&px);
    np_show(&px);

    ESP_LOGW(TAG, "UI initialized on pin %d", gpio_pin);

    return ASIO_OK;
}

static asio_result_t led_ui_destroy()
{
    vQueueDelete(led_ui_obj->ui_queue);
    free(led_ui_obj);
    // ws2812_destroy(gpio_pin);

    return ASIO_OK;
}

