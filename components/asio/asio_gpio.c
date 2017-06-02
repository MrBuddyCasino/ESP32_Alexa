/*
 * asioi_queue.c
 *
 *  Created on: 30.05.2017
 *      Author: michaelboeckling
 */

#include "stdlib.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_log.h"
#include "esp_system.h"
#include "driver/gpio.h"

#include "url_parser.h"
#include "asio.h"
#include "asio_gpio.h"

#define TAG "asio_gpio"
#define ESP_INTR_FLAG_DEFAULT 0


typedef struct {
    xQueueHandle gpio_evt_queue;
    gpio_num_t gpio_num;
    asio_gpio_handler_t callback;
} asio_gpio_context_t;


/* gpio event handler */
static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    asio_gpio_context_t *gpio_ctx = arg;

    xQueueSendToBackFromISR(gpio_ctx->gpio_evt_queue, &gpio_ctx->gpio_num, &xHigherPriorityTaskWoken);

    if(xHigherPriorityTaskWoken) {
        portYIELD_FROM_ISR();
    }
}


void asio_gpio_init(asio_task_t *conn)
{
    asio_gpio_context_t *gpio_ctx = conn->io_ctx;

    gpio_config_t io_conf;

    //interrupt of rising edge
    io_conf.intr_type = GPIO_PIN_INTR_POSEDGE;
    //bit mask of the pins, use GPIO0 here ("Boot" button)
    io_conf.pin_bit_mask = (1 << gpio_ctx->gpio_num);
    //set as input mode
    io_conf.mode = GPIO_MODE_INPUT;
    //disable pull-down mode
    io_conf.pull_down_en = 0;
    //enable pull-up mode
    io_conf.pull_up_en = 1;
    gpio_config(&io_conf);

    //install gpio isr service
    gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);

    // remove existing handler that may be present
    gpio_isr_handler_remove(gpio_ctx->gpio_num);

    //hook isr handler for specific gpio pin
    gpio_isr_handler_add(gpio_ctx->gpio_num, gpio_isr_handler, gpio_ctx);
}


void asio_gpio_destroy(asio_task_t *conn)
{
    asio_gpio_context_t *gpio_ctx = conn->io_ctx;

    // TODO: remove isr_service?
    gpio_isr_handler_remove(gpio_ctx->gpio_num);
    vQueueDelete(gpio_ctx->gpio_evt_queue);
    free(conn->io_ctx);
}


void asio_gpio_run(asio_task_t *conn)
{
    asio_gpio_context_t *gpio_ctx = conn->io_ctx;
    uint32_t io_num;

    if (xQueueReceive(gpio_ctx->gpio_evt_queue, &io_num, (TickType_t) 0)) {
        // printf("GPIO[%d] intr, val: %d\n", io_num, gpio_get_level(io_num));
        //ESP_LOGI(TAG, "RAM left %d", esp_get_free_heap_size());

        gpio_ctx->callback(io_num, conn->user_data);
    }
}


asio_result_t *asio_gpio_event(asio_task_t *conn)
{
    switch(conn->state)
    {
        case ASIO_TASK_NEW:
            asio_gpio_init(conn);
            conn->state = ASIO_TASK_RUNNING;
            break;

        case ASIO_TASK_RUNNING:
            asio_gpio_run(conn);
            break;

        case ASIO_TASK_STOPPING:
            asio_gpio_destroy(conn);
            break;

        default:
            break;
    }

    return ASIO_OK;
}


asio_task_t *asio_new_gpio_task(asio_registry_t *registry, gpio_num_t gpio_num, asio_gpio_handler_t callback, void *user_data)
{
    asio_task_t *conn = calloc(1, sizeof(asio_task_t));
    if(conn == NULL) {
        ESP_LOGE(TAG, "calloc() failed: asio_connection_t");
        return NULL;
    }

    conn->registry = registry;
    conn->io_handler = asio_gpio_event;
    conn->state = ASIO_TASK_NEW;
    conn->user_data = user_data;

    asio_gpio_context_t *gpio_ctx = calloc(1, sizeof(asio_gpio_context_t));
    conn->io_ctx = gpio_ctx;
    gpio_ctx->callback = callback;
    gpio_ctx->gpio_num = gpio_num;
    gpio_ctx->gpio_evt_queue = xQueueCreate(1, sizeof(gpio_num_t));

    if(asio_registry_add_task(registry, conn) < 0) {
        ESP_LOGE(TAG, "failed to add connection");
        asio_registry_remove_task(conn);
        return NULL;
    }

    return conn;
}
