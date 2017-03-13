/*
 * audio_player.c
 *
 *  Created on: 12.03.2017
 *      Author: michaelboeckling
 */


#include <stdlib.h>
#include "freertos/FreeRTOS.h"

#include "audio_player.h"
#include "spiram_fifo.h"
#include "freertos/task.h"
#include "mp3_decoder.h"


/* comm via fifo */

#define PRIO_MAD configMAX_PRIORITIES - 2


static int t;
static bool mad_started = false;
int stream_reader(char *recv_buf, ssize_t bytes_read, void *user_data)
{
    player_t *player = user_data;

    if (bytes_read > 0) {
        spiRamFifoWrite(recv_buf, bytes_read);
    }

    if (!mad_started && (spiRamFifoFree() < spiRamFifoLen()/2) && player->state == PLAYING)
    {
        //Buffer is filled. Start up the MAD task. Yes, the 2100 words of stack is a fairly large amount but MAD seems to need it.
        if (xTaskCreatePinnedToCore(&task_mad, "tskmad", 6300, player, PRIO_MAD, NULL, 1) != pdPASS)
        {
            printf("ERROR creating MAD task! Out of memory?\n");
        } else {
            printf("created MAD task\n");
        }
        mad_started = true;
    }


    t = (t+1) & 255;
    if (t == 0) {
        // printf("Buffer fill %d, buff underrun ct %d\n", spiRamFifoFill(), (int)bufUnderrunCt);
        printf("Buffer fill %d\n", spiRamFifoFill());
    }

    return 0;
}

void mp3_player_init(renderer_sink_t sink)
{
    ;
}
