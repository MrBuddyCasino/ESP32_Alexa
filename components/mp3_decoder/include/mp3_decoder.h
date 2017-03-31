/*
 * mp3_decoder.c
 *
 *  Created on: 13.03.2017
 *      Author: michaelboeckling
 */

// The mp3 read buffer size. The theoretical maximum frame size is 2881 bytes,
// MPEG 2.5 Layer II, 8000 Hz @ 160 kbps, with a padding slot plus 8 byte MAD_BUFFER_GUARD.
#define MAX_FRAME_SIZE (2889)

// theoretical minimum frame size plus 8 byte MAD_BUFFER_GUARD
#define MIN_FRAME_SIZE (32)

void mp3_decoder_task(void *pvParameters);
