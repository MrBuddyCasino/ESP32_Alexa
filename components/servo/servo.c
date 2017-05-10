/*
 * servo.c
 *
 *  Created on: 02.04.2017
 *      Author: michaelboeckling
 */

#include <math.h>
#include "driver/ledc.h"
#include "esp_err.h"

#define MOTOR_PWM_CHANNEL LEDC_CHANNEL_2
#define MOTOR_PWM_TIMER LEDC_TIMER_1
#define MOTOR_PWM_BIT_NUM LEDC_TIMER_10_BIT

#define PWM_PIN GPIO_NUM_23

void motor_pwm_init(void)
{
    ledc_channel_config_t ledc_channel = { 0 };

    ledc_channel.gpio_num = PWM_PIN;
    ledc_channel.speed_mode = LEDC_HIGH_SPEED_MODE;
    ledc_channel.channel = MOTOR_PWM_CHANNEL;
    ledc_channel.intr_type = LEDC_INTR_DISABLE;
    ledc_channel.timer_sel = MOTOR_PWM_TIMER;
    ledc_channel.duty = 0;

    ledc_timer_config_t ledc_timer = { 0 };
    ledc_timer.speed_mode = LEDC_HIGH_SPEED_MODE;
    ledc_timer.bit_num = MOTOR_PWM_BIT_NUM;
    ledc_timer.timer_num = MOTOR_PWM_TIMER;
    ledc_timer.freq_hz = 22050;

    ESP_ERROR_CHECK(ledc_channel_config(&ledc_channel));
    ESP_ERROR_CHECK(ledc_timer_config(&ledc_timer));
}

void motor_pwm_set(uint32_t duty)
{
    ESP_ERROR_CHECK(
            ledc_set_duty(LEDC_HIGH_SPEED_MODE, MOTOR_PWM_CHANNEL, duty));
    ESP_ERROR_CHECK(
            ledc_update_duty(LEDC_HIGH_SPEED_MODE, MOTOR_PWM_CHANNEL));
}

void filter()
{
    // combine channels
    // uint32_t duty = ((uint16_t) sample_buff_ch0[i] + (uint16_t) sample_buff_ch1[i]) / 2;

    // scale to 10 bits and clear top bits
    // duty = ((duty >> 6) & 1023);

    // reduce degrees of rotation from 120° to 30°
    // duty = duty / 4;

    // motor_pwm_set(duty);
}
