/*
 * ONICS
 * Copyright 2017
 * Christopher Adam Telfer
 *
 * pmlparse.h -- PML parser external interface
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
#ifndef __PMLPARSE_H
#define __PMLPARSE_H

#include <stdio.h>
#include <cat/cat.h>

struct pml_parser;
struct pml_ast;

typedef void (*pmlp_eoi_f)(struct pml_parser *pmlp);


struct pml_parser *pmlp_alloc(void);

/*
 * Reset the import path the parser.
 */

void pmlp_ipath_reset(struct pml_parser *pmlp);


/*
 * Append a directory to the import path.
 */
int pmlp_ipath_append(struct pml_parser *pmlp, const char *dir);


/*
 * Reset the input stream for the parser
 */
void pmlp_reset_input(struct pml_parser *pmlp);


/* 
 * Add an input string to the queue.  If 'front' is non-zero then add to the 
 * front of the queue, otherwise add to the back.
 */
int pmlp_add_instring(struct pml_parser *pmlp, const char *s, int front,
		      const char *name);


/*
 * Add an input file to the queue.  If 'front' is non-zero then add it to
 * front of the queue, otherwise add it to the back. The scanner will read
 * this file until EOF and then close it.
 */
int pmlp_add_infile(struct pml_parser *pmlp, FILE *f, int front,
		    const char *name);


/*
 * Open the file named 'fn' and add it to the lex input as above with
 * pmlp_add_infile().  This routine searches the library search path
 * for the file if it can't open the base file name.
 */
int pmlp_open_add_infile(struct pml_parser *pmlp, const char *fn, int front);


/* set a callback to invoke on end of input */
void pmlp_set_eoicb(struct pml_parser *pmlp, pmlp_eoi_f f);


/*
 * Parse the current input until completion and store the result in ast.
 */
int pmlp_parse(struct pml_parser *pmlp, struct pml_ast *ast);


/*
 * Free the parser and its associated metadata
 */
void pmlp_free(struct pml_parser *pmlp);



/*
 * Enable or disable debug in the parser.
 */
void pmlp_set_debug(struct pml_parser *pmlp, int on);


/*
 * Return a reference to the error buffer.
 */
const char *pmlp_get_error(struct pml_parser *pmlp);


#endif /* __PMLPARSE_H */
