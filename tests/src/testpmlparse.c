/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * testpmlparse.c -- Test the basic PML parsing and debug the AST.  Does not
 *   include code generation testing.
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
#include <stdlib.h>
#include <string.h>

#include <cat/err.h>

#include "prid.h"
#include "pmltree.h"
#include "pmllex.h"
#include "stdproto.h"

#define VERBOSE		1
#define LEX		2
#define TREE1		4
#define TREE2		8

extern void PMLTrace(FILE *trace, char *pfx);

int main(int argc, char *argv[])
{
	int tok;
	struct pmllex *scanner;
	pml_parser_t parser;
	struct pml_ast tree;
	struct pmll_val extra;
	int printmask = VERBOSE|LEX|TREE1|TREE2;

	if (argc > 1) {
		if (strcmp(argv[1], "-h") == 0) {
			fprintf(stderr, "usage: %s <printmask>\n"
					"\tBit 0: enables verbose\n"
					"\tBit 1: enables lex analyzer output\n"
					"\tBit 2: prints pre-optimized AST\n"
					"\tBit 3: prints optimized AST\n",
				argv[0]);
			exit(1);
		}
		printmask = atoi(argv[1]);
	}

	if (printmask & VERBOSE) {
		printf("#########\n");
		printf("Initializing parse data structures\n");
		printf("#########\n");
	}

	register_std_proto();

	if ((scanner = pmll_alloc()) == NULL)
		errsys("pmllex_init:");
	if (pmll_add_infile(scanner, stdin, 0, "-") < 0)
		errsys("pmll_add_input_file:");

	if (!(parser = pml_alloc()))
		errsys("pml_alloc:");
	pml_ast_init(&tree);
	pml_ast_add_std_intrinsics(&tree);
	pml_ast_set_parser(&tree, scanner, parser);

	if (printmask & VERBOSE) {
		printf("#########\n");
		printf("Starting Parse\n");
		printf("#########\n");
	}

	if (printmask & LEX)
		PMLTrace(stdout, "  ---  ");

	do {
		tok = pmll_nexttok(scanner, &extra);
		if (tok < 0)
			err("Syntax error: %s\n", pmll_get_err(scanner));
		if (printmask & LEX)
			printf("Token -- %d -> '%s'\n", tok,
			       pmll_get_text(scanner));
		if (pml_parse(parser, &tree, tok, extra)) {
			err("parse error on file %s line %d: %s\n",
			    pmll_get_iname(scanner),
			    pmll_get_lineno(scanner), tree.errbuf);
		}
	} while (tok > 0);

	if (!tree.done)
		err("File did not reduce to a complete tree\n");

	if (printmask & VERBOSE) {
		printf("\n\n########\n");
		printf("Done parsing, destroying scanner and parser\n");
		printf("########\n");
	}

	if (printmask & TREE1) {
		if (printmask & VERBOSE) {
			printf("\n\n########\n");
			printf("Printing base tree\n");
			printf("#########\n");
		}
		pml_ast_print(&tree);
	}

	if (printmask & TREE2) {
		if (printmask & VERBOSE) {
			printf("\n\n########\n");
			printf("Optimizing tree:\n");
			printf("########\n");
		}

		if (pml_ast_optimize(&tree) < 0)
			err("Error optimizing PML tree: %s\n", tree.errbuf);

		if (printmask & VERBOSE) {
			printf("Done... printing optimized tree\n");
		}

		pml_ast_print(&tree);
	}

	if (printmask & VERBOSE) {
		printf("\n\n########\n");
		printf("Clearing tree:\n");
		printf("########\n");
	}

	pml_ast_clear(&tree);

	return 0;
}
