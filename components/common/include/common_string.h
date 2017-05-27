/*
 * common_string.h
 *
 *  Created on: 26.05.2017
 *      Author: michaelboeckling
 */

#ifndef _INCLUDE_COMMON_STRING_H_
#define _INCLUDE_COMMON_STRING_H_

bool starts_with(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}


#endif /* _INCLUDE_COMMON_STRING_H_ */
