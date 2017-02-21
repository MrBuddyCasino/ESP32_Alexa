/*
 * alexa.c
 *
 *  Created on: 17.02.2017
 *      Author: michaelboeckling
 */

#include <stdint.h>
#include <stddef.h>
#include "nghttp-client.h"


typedef struct {
    http2_session_data *http2_session;
} alexa_session;


/* Europe: alexa-eu / America: alexa-na */
const char *uri_directives = "https://avs-alexa-eu.amazon.com/v20160207/directives";
const char *uri_events = "https://avs-alexa-eu.amazon.com/v20160207/events";





void init()
{
    alexa_session *alexa_session = calloc(1, sizeof(alexa_session));
}
