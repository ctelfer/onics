#include "pmltree.h"

int main(int argc, char *argv[])
{
	int tok;
	pml_scanner_t scanner;
	pml_parser_t parser;
	struct pml_ast tree;
	struct pml_lex_val none, extra;

	pml_lexv_init(&none);
	if (pmllex_init(&scanner))
		errsys("pmllex_init:");
	pmlset_in(stdin, scanner);
	pmlset_extra(none, scanner);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc:");
	pml_ast_init(&tree);

	while ((tok = pmllex(scanner)) > 0) {
		extra = pmlget_extra(scanner);
		printf("-- %d -> '%s'\n", tok, pmlget_text(scanner));
		if (pml_parse(parser, &tree, tok, extra)) {
			err("parse error on line %d\n",
			    pmlget_lineno(scanner));
		}
		pmlset_extra(none, scanner);
	}
	pmllex_destroy(scanner);

	return 0;
}
