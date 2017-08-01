/*
 * asio_generic.h
 *
 *  Created on: 30.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_ASIO_GENERIC_H_
#define _INCLUDE_ASIO_GENERIC_H_

typedef asio_result_t (*asio_generic_callback_t)(asio_task_t *conn, void *arg, void *user_data);

asio_task_t *asio_new_generic_task(char *name, asio_registry_t *registry, asio_generic_callback_t callback, void *cb_arg, void *user_data);

#endif /* _INCLUDE_ASIO_GENERIC_H_ */
