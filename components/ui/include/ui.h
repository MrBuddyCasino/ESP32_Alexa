/*
 * ui.h
 *
 *  Created on: 01.04.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_UI_H_
#define _INCLUDE_UI_H_

typedef enum { UI_NONE, UI_CONNECTING, UI_CONNECTED, UI_RECOGNIZING_SPEECH, UI_SYNTHESIZING_SPEECH } ui_event_t;

void ui_queue_event(ui_event_t evt);
int led_ui_init(gpio_num_t gpio_pin, uint16_t num_leds);
void led_ui_run();

#endif /* _INCLUDE_UI_H_ */
