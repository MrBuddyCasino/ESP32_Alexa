/*
 * asio_led_ui.c
 *
 *  Created on: 05.06.2017
 *      Author: michaelboeckling
 */

#include <inttypes.h>
#include <sys/timeb.h>
#include "driver/gpio.h"
#include "ui.h"
#include "url_parser.h"
#include "asio.h"

asio_result_t on_led_ui_cb(asio_task_t *task, void *arg, void *user_data)
{
    gpio_num_t gpio_pin = (gpio_num_t) arg;
    gpio_pin = GPIO_NUM_21;

    switch(task->state)
    {
        case ASIO_TASK_NEW:
            led_ui_init(gpio_pin, 2);
            task->state = ASIO_TASK_RUNNING;
        break;

        case ASIO_TASK_RUNNING:
            led_ui_run();
            break;

        case ASIO_TASK_STARTING:
        case ASIO_TASK_STOPPING:
        case ASIO_TASK_STOPPED:
            break;
    }

    return ASIO_OK;
}
