#include "pmltree.h"
#include "stdproto.h"

#define VERBOSE		1
#define LEX		2
#define TREE1		4
#define TREE2		8

extern void PMLTrace(FILE *trace, char *pfx);

int main(int argc, char *argv[])
{
	int tok;
	pml_scanner_t scanner;
	pml_parser_t parser;
	struct pml_ast tree;
	struct pml_lex_val none, extra;
	int printmask = VERBOSE|LEX|TREE1|TREE2;

	if (argc > 1)
		printmask = atoi(argv[1]);

	if (printmask & VERBOSE) {
		printf("n########\n");
		printf("Initializing parse data structures\n");
		printf("#########\n");
	}

	register_std_proto();

	pml_lexv_init(&none);
	if (pmllex_init(&scanner))
		errsys("pmllex_init:");
	pmlset_in(stdin, scanner);
	pmlset_extra(none, scanner);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc:");
	pml_ast_init(&tree);

	if (printmask & VERBOSE) {
		printf("n########\n");
		printf("Starting Parse\n");
		printf("#########\n");
	}

	if (printmask & LEX)
		PMLTrace(stdout, "  ---  ");

	do {
		tok = pmllex(scanner);
		if (tok < 0)
			err("Encountered invalid token on line %d\n",
			    pmlget_lineno(scanner));
		extra = pmlget_extra(scanner);
		if (printmask & LEX)
			printf("Token -- %d -> '%s'\n", tok,
			       pmlget_text(scanner));
		if (pml_parse(parser, &tree, tok, extra)) {
			err("parse error on line %d: %s\n",
			    pmlget_lineno(scanner), tree.errbuf);
		}
		pmlset_extra(none, scanner);
	} while (tok > 0);

	if (!tree.done)
		err("File did not reduce to a complete tree\n");

	if (printmask & VERBOSE) {
		printf("\n\n########\n");
		printf("Done parsing, destroying scanner and parser\n");
		printf("########\n");
	}

	pmllex_destroy(scanner);
	pml_free(parser);

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
