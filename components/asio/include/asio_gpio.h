/*
 * asio_gpio.h
 *
 *  Created on: 30.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_GPIO_H_
#define _INCLUDE_ASIO_GPIO_H_

typedef void (*asio_gpio_handler_t)(gpio_num_t io_num, void *user_data);

asio_task_t *asio_new_gpio_task(asio_registry_t *registry, gpio_num_t gpio_num, asio_gpio_handler_t callback, void *user_data);

#endif /* _INCLUDE_ASIO_GPIO_H_ */
