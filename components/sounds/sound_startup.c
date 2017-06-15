/*
 * startup.c
 *
 *  Created on: 21.05.2017
 *      Author: michaelboeckling
 */

#include <stdbool.h>
#include "common_buffer.h"
#include "audio_player.h"

/* embedded file */
//extern uint8_t file_start[] asm("_binary_coin_mp3_start");
//extern uint8_t file_end[] asm("_binary_coin_mp3_end");

extern uint8_t file_start[] asm("_binary_laugh_mp3_start");
extern uint8_t file_end[] asm("_binary_laugh_mp3_end");

void play_sound(player_t *player_config)
{
    player_config->media_stream->eof = false;
    player_config->media_stream->content_type = AUDIO_MPEG;

    audio_player_start(player_config);

    uint8_t *pos = file_start;
    size_t remaining = file_end - pos;

    size_t block_size = 4096;
    while(remaining > block_size)
    {
        size_t length = min(remaining, block_size);
        audio_stream_consumer((const char *) pos, length, player_config);
        pos += length;
        remaining = file_end - pos;
    }
    player_config->media_stream->eof = true;

    // audio_player_stop();
}
