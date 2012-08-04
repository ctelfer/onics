/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * testpmllex.c -- Unit test for the PML lexical analyzer.
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
#include <stdio.h>
#include "pml.h"
#include "pmllex.h"

extern const char *pml_tok_strs[];


const char *strof(struct pmll_val *v, int tok, char *buf, size_t bsize)
{
	byte_t *bp;
	uint16_t *wp;


	if (tok == PMLTOK_IPV4ADDR) {
		bp = v->u.v4addr;
		snprintf(buf, bsize, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]);
		return buf;
	} else if (tok == PMLTOK_IPV6ADDR) { 
		bp = v->u.v6addr;
		snprintf(buf, bsize, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		         (bp[0] << 8) | bp[1], 
		         (bp[2] << 8) | bp[3], 
		         (bp[4] << 8) | bp[5], 
		         (bp[6] << 8) | bp[7], 
		         (bp[8] << 8) | bp[9], 
		         (bp[10] << 8) | bp[11], 
		         (bp[12] << 8) | bp[13], 
		         (bp[14] << 8) | bp[15]);
		return buf;
	} else if (tok == PMLTOK_ETHADDR) { 
		bp = v->u.ethaddr;
		snprintf(buf, bsize, "%02x:%02x:%02x:%02x:%02x:%02x",
			 bp[0], bp[1], bp[2], bp[3], bp[4], bp[5]);
		return buf;
	} else if (tok == PMLTOK_NUM) { 
		snprintf(buf, bsize, "%llu", (ullong)v->u.num);
		return buf;
	} else {
		return NULL;
	}
}


int main(int argc, char *argv[])                                                                    
{       
        int x;
	char buf[256];
	const char *s;
	struct pmllex *lex;
	struct pmll_val v;

	lex = pmll_alloc();
        if (lex == NULL)
                errsys("pmll_new():");                                             

	if (pmll_add_infile(lex, stdin, 0, "stdin") < 0)
		errsys("pmll_add_input_file():");

        while ( (x = pmll_nexttok(lex, &v)) > 0 ) {
                printf("%-15s'%s'", pml_tok_strs[x], pmll_get_text(lex));
		s = strof(&v, x, buf, sizeof(buf));
		if (s != NULL)
			printf(" -- '%s'\n", s);
		else
			printf("\n");
		pmllv_clear(&v);
	}
        if ( x < 0 ) {
                printf("unknown token on line: %lu\n", pmll_get_lineno(lex));       
		printf("\t%s\n", pmll_get_err(lex));
        } else {
                printf("End of file\n");                                            
        }
        pmll_free(lex);                                                    

        return 0;                                                                   
}
