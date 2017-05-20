/*
 * multipart_producer.c
 *
 *  Created on: 19.05.2017
 *      Author: michaelboeckling
 */

#include "common_buffer.h"

#define NL "\r\n"
#define BOUNDARY_TERM "nghttp2123456789"
#define BOUNDARY_LINE NL "--" BOUNDARY_TERM NL
#define BOUNDARY_EOF NL "--" BOUNDARY_TERM "--" NL
#define HDR_FORM_DATA "multipart/form-data; boundary=\"" BOUNDARY_TERM "\""

#define HDR_DISP_META "Content-Disposition: form-data; name=\"metadata\"" NL
#define HDR_TYPE_JSON "Content-Type: application/json; charset=UTF-8" NL
#define META_DATA_HEADERS HDR_DISP_META HDR_TYPE_JSON NL
#define JSON_PART_PREFIX BOUNDARY_LINE META_DATA_HEADERS

#define HDR_DISP_AUDIO "Content-Disposition: form-data; name=\"audio\"" NL
#define HDR_TYPE_OCTET "Content-Type: application/octet-stream" NL
#define AUDIO_DATA_HEADERS HDR_DISP_AUDIO HDR_TYPE_OCTET NL
#define AUDIO_PART_PREFIX BOUNDARY_LINE AUDIO_DATA_HEADERS

/*
size_t multipart_start(buffer_t *buf)
{
    char *ptr = BOUNDARY_LINE;
    return buf_write(buf, ptr, sizeof(BOUNDARY_LINE) - 1);
}
*/

size_t begin_part_meta_data(buffer_t *buf)
{
    char *ptr = JSON_PART_PREFIX;
    return buf_write(buf, ptr, sizeof(JSON_PART_PREFIX) - 1);
}

size_t begin_part_audio_data(buffer_t *buf)
{
    char *ptr = AUDIO_PART_PREFIX;
    return buf_write(buf, ptr, sizeof(AUDIO_PART_PREFIX) - 1);
}
/*
size_t multipart_hdr_content_disposition(buffer_t *buf, char *name)
{
    char *pre = "Content-Disposition: form-data; name=\"";
    size_t bytes_written = buf_write(buf, pre, strlen(pre));

    bytes_written += buf_write(buf, name, strlen(name));

    char *post = "\"" NL;
    bytes_written += buf_write(buf, name, strlen(name));

    return bytes_written;
}

size_t multipart_hdr_content_type(buffer_t *buf, char *type)
{
    char *pre = "Content-Type: ";
    size_t bytes_written = buf_write(buf, pre, strlen(pre));
    bytes_written += buf_write(buf, type, strlen(type));
    bytes_written += buf_write(buf, NL, strlen(NL));

    return bytes_written;
}
*/

size_t multipart_end(buffer_t *buf)
{
    char *ptr = BOUNDARY_EOF;
    return buf_write(buf, ptr, sizeof(BOUNDARY_EOF) - 1);
}
