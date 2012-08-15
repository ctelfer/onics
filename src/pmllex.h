/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * pmllex.h -- Header for the lexical analyzer for PML
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __PMLLEX_H
#define __PMLLEX_H

#include <stdio.h>
#include <cat/cat.h>
#include <cat/cattypes.h>

#define PMLLV_SCALAR	0
#define PMLLV_STRING	1

struct pmllex;

typedef void (*pmll_eoi_f)(struct pmllex *lex);

struct pmll_val {
	int type;
	union {
		byte_t v6addr[16];
		byte_t ethaddr[6];
		uint64_t num;
		byte_t v4addr[4];
		struct raw raw;
	} u;
};


/* initialize a scanner auxilliary value */
void pmllv_init(struct pmll_val *v);

/* clear a scanner auxilliary value */
void pmllv_clear(struct pmll_val *v);



/* Allocate a lexical scanner */
struct pmllex *pmll_alloc(void);

/* Free a lexical scanner and all associated data */
void pmll_free(struct pmllex *lex);

/* 
 * Add an input string to the queue.  If 'front' is non-zero then add to the 
 * front of the queue, otherwise add to the back.
 */
int pmll_add_instr(struct pmllex *lex, const char *s, int front,
		   const char *name);

/*
 * Add an input file to the queue.  If 'front' is non-zero then add it to
 * front of the queue, otherwise add it to the back. The scanner will read
 * this file until EOF and then close it.
 */
int pmll_add_infile(struct pmllex *lex, FILE *f, int front,
		    const char *name);

/* Get the error string for the scanner */
const char *pmll_get_err(struct pmllex *lex);

/* get the next token from input and its associated value */
int pmll_nexttok(struct pmllex *lex, struct pmll_val *val);

/* get the text that matched the current token */
const char *pmll_get_text(struct pmllex *lex);

/* get the line number of the input */
ulong pmll_get_lineno(struct pmllex *lex);

/* get the name of the current input */
const char *pmll_get_iname(struct pmllex *lex);

/* Set opaque context for the scanner */
void pmll_set_ctx(struct pmllex *lex, void *ctx);

/* get opaque context for the scanner */
void *pmll_get_ctx(struct pmllex *lex);

/* set a callback to invoke on end of input */
void pmll_set_eoicb(struct pmllex *lex, pmll_eoi_f f);

#endif /* __PMLLEX_H */
