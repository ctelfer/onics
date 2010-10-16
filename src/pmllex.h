/*
   pmllex.h -- common definitions for lexical analysis interface
 */

#ifndef __pmllex_h
#define __pmllex_h

#include <cat/cat.h>

#define PMLLV_SCALAR	0
#define PMLLV_STRING	1

struct pml_lex_val {
	int type;
	union {
		byte_t v6addr[16];
		byte_t ethaddr[6];
		unsigned long num;
		byte_t v4addr[4];
		struct raw raw;
	} u;
};

#endif /* __pmllex_h */
