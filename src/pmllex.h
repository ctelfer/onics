/*
   pmllex.h -- common definitions for lexical analysis interface
 */

#ifndef __pmllex_h
#define __pmllex_h

#include <cat/cat.h>

union pmllex_u {
	byte_t v6addr[16];
	byte_t ethaddr[6];
	unsigned long num;
	byte_t v4addr[4];
	struct raw raw;
};

#endif /* __pmllex_h */
