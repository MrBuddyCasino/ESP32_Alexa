/*
 * servo.h
 *
 *  Created on: 01.04.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_SERVO_H_
#define _INCLUDE_SERVO_H_

void motor_pwm_init(void);
void motor_pwm_set(float duty_fraction);

#endif /* _INCLUDE_SERVO_H_ */
