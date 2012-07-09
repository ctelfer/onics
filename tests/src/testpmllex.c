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


typedef void *pml_scanner_t;
typedef void *pml_buffer_t;
int pmllex_init(pml_scanner_t *);
void pmlset_in(FILE *input, pml_scanner_t);
pml_buffer_t pml_scan_string(const char *, pml_scanner_t);
void pml_delete_buffer(pml_buffer_t, pml_scanner_t);
int pmllex(pml_scanner_t);
struct pml_lex_val pmlget_extra(pml_scanner_t);
void pmlset_extra(struct pml_lex_val v, pml_scanner_t);
const char *pmlget_text(pml_scanner_t);
int pmlget_lineno(pml_scanner_t);
void pmllex_destroy(pml_scanner_t);

extern const char *pml_tok_strs[];


int pmlwrap(void)
{
	return 1;
}


int testpmllex()                                                                    
{       
        int x;
        pml_scanner_t scanner;
        if ( pmllex_init(&scanner) )
                errsys("pmllex_init:");                                             
        pmlset_in(stdin, scanner);
        while ( (x = pmllex(scanner)) > 0 )
                printf("%-15s'%s'\n", pml_tok_strs[x], pmlget_text(scanner));       
        if ( x < 0 ) {
                printf("unknown char on line: %d\n", pmlget_lineno(scanner));       
        } else {
                printf("End of file\n");                                            
        }
        pmllex_destroy(scanner);                                                    
        return 0;                                                                   
}

int main(int argc, char *argv[])
{
	return testpmllex();
}
