/*
 * multipart_producer.h
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_MULTIPART_PRODUCER_H_
#define _INCLUDE_MULTIPART_PRODUCER_H_

#define BOUNDARY_TERM "nghttp2123456789"
#define HDR_FORM_DATA "multipart/form-data; boundary=\"" BOUNDARY_TERM "\""

size_t begin_part_meta_data(buffer_t *buf);
size_t begin_part_audio_data(buffer_t *buf);
size_t multipart_end(buffer_t *buf);


#endif /* _INCLUDE_MULTIPART_PRODUCER_H_ */
