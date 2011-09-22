#include "pmltree.h"
#include "stdproto.h"

extern void PMLTrace(FILE *trace, char *pfx);

int main(int argc, char *argv[])
{
	int tok;
	pml_scanner_t scanner;
	pml_parser_t parser;
	struct pml_ast tree;
	struct pml_lex_val none, extra;

	register_std_proto();
	pml_lexv_init(&none);
	if (pmllex_init(&scanner))
		errsys("pmllex_init:");
	pmlset_in(stdin, scanner);
	pmlset_extra(none, scanner);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc:");
	pml_ast_init(&tree);

	PMLTrace(stderr, "  ---  ");

	do {
		tok = pmllex(scanner);
		if (tok < 0)
			err("Encountered invalid token on line %d\n",
			    pmlget_lineno(scanner));
		extra = pmlget_extra(scanner);
		printf("Token -- %d -> '%s'\n", tok, pmlget_text(scanner));
		if (pml_parse(parser, &tree, tok, extra)) {
			err("parse error on line %d: %s\n",
			    pmlget_lineno(scanner), tree.errbuf);
		}
		pmlset_extra(none, scanner);
	} while (tok > 0);

	if (!tree.done)
		err("File did not reduce to a complete tree\n");

	printf("Done parsing, destroying scanner and parser\n");

	pmllex_destroy(scanner);
	pml_free(parser);

	if (pml_ast_resolve(&tree) < 0)
		err("parse error during resolution: %s\n", tree.errbuf);

	pml_ast_print(&tree);

	pml_ast_clear(&tree);

	return 0;
}
