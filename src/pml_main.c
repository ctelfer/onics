#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include <cat/emalloc.h>

#include "prid.h"
#include "pktbuf.h"
#include "protoparse.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_prog.h"
#include "pmltree.h"
#include "pmlncg.h"


struct clopt options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"),
	CLOPT_INIT(CLOPT_NOARG, 'e', "--ignore-err", "ignore netvm errors"),
	CLOPT_INIT(CLOPT_NOARG, 'v', "--verbose", "increase verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 'q', "--quiet", "decrease verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 's', "--step", "single step the program"),
	CLOPT_INIT(CLOPT_STRING, 'i', "--infile", "input file"),
	CLOPT_INIT(CLOPT_STRING, 'c', "--compile", 
		   "compile to netvm program file"),
};

struct clopt_parser optparser =
	CLOPTPARSER_INIT(options, array_length(options));


uint64_t vm_stack[1024];
int verbosity = 0;
int ignore_errors = 0;
int single_step = 0;
char *progname;
const char *ofname = NULL;
const char *ifname = NULL;


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: pml [options]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s\n", buf);
	exit(1);
}


void parse_options(int argc, char *argv[])
{
	struct clopt *opt;
	int rv;
	optparse_reset(&optparser, argc, argv);
	while (!(rv = optparse_next(&optparser, &opt))) {
		if (opt->ch == 'h') {
			usage();
		} else if (opt->ch == 'e') {
			ignore_errors = 1;
	        } else if (opt->ch == 'v') {
			++verbosity;
		} else if (opt->ch == 'q') {
			--verbosity;
		} else if (opt->ch == 'i') {
			ifname = opt->val.str_val;
		} else if (opt->ch == 'c') {
			ofname = opt->val.str_val;
		} else if (opt->ch == 's') {
			single_step = 1;
		}
	}
	if (rv != argc)
		usage();
}


void parse_pml_program(FILE *f, struct netvm_program *prog)
{
	int tok;
	pml_scanner_t scanner;
	pml_parser_t parser;
	struct pml_ast ast;
	struct pml_lex_val none, extra;
	
	pml_lexv_init(&none);
	if (pmllex_init(&scanner))
		errsys("pmllex_init: ");
	pmlset_in(f, scanner);
	pmlset_extra(none, scanner);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc: ");
	pml_ast_init(&ast);

	if (verbosity > 0)
		fprintf(stderr, "Starting program parse\n");

	do {
		tok = pmllex(scanner);
		if (tok < 0)
			err("Encountered invalid token on line %d\n",
			    pmlget_lineno(scanner));
		extra = pmlget_extra(scanner);
		if (pml_parse(parser, &ast, tok, extra)) {
			err("parse error on line %d: %s\n",
			    pmlget_lineno(scanner), ast.errbuf);
		}
		pmlset_extra(none, scanner);
	} while (tok > 0);

	if (!ast.done)
		err("Program file is not a complete PML program\n");

	pmllex_destroy(scanner);
	pml_free(parser);

	/* TODO: modify pml_ast_print() to take a file to print to files */

	if (verbosity > 0)
		fprintf(stderr, "done parsing:  optimizing the program\n");

	if (pml_ast_optimize(&ast) < 0)
		err("Error optimizing PML tree: %s\n", ast.errbuf);

	nvmp_init(prog);
	if (pml_to_nvmp(&ast, prog, 0) < 0)
		errsys("Error generating code in pml_to_nvmp: ");
}


void initvm(struct netvm *vm, uint64_t *stk, uint stksz, 
	    struct netvm_std_coproc *cproc, struct file_emitter *fe,
	    struct netvm_program *prog)
{
	int i;
	int rv;
	uint len;
	uint perms;

	netvm_init(vm, stk, stksz);
	if (init_netvm_std_coproc(vm, cproc) < 0)
		errsys("Error initializing NetVM coprocessors: ");
	file_emitter_init(fe, stderr);
	set_outport_emitter(&cproc->outport, &fe->fe_emitter);

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		len = prog->sdescs[i].len;
		perms = prog->sdescs[i].perms;
		if (perms != 0)
			netvm_set_mseg(vm, i, emalloc(len), len, perms);
	}

	if ((rv = nvmp_validate(vm, prog)) < 0)
		err("Error validating program: %s\n", netvm_estr(rv));


}


int main(int argc, char *argv[])
{
	struct netvm vm;
	uint64_t vmstk[1024];
	struct netvm_std_coproc cproc;
	struct file_emitter fe;
	struct netvm_program prog;
	FILE *fin, *fout;
	int flags = 0;

	parse_options(argc, argv);

	register_std_proto();
	pkb_init(1);

	if (ifname != NULL) {
		if ((fin = fopen(ifname , "r")) == NULL)
			errsys("error opening input file '%s': ", ifname);
	} else {
		fin = stdin;
	}

	parse_pml_program(fin, &prog);
	fclose(fin);

	if (ofname != NULL) {

		if ((fout = fopen(ofname, "w")) == NULL)
			errsys("error opening output file '%s': ", ofname);
		if (nvmp_write(&prog, fout) < 0)
			errsys("error writing out program: ");
		fclose(fout);
		nvmp_clear(&prog);

	} else {

		initvm(&vm, vmstk, array_length(vmstk), &cproc, &fe, &prog);

		if (ignore_errors)
			flags |= NVMP_RUN_IGNORE_ERR;
		if (single_step)
			flags |= NVMP_RUN_SINGLE_STEP;
		if (verbosity > 0)
			flags |= NVMP_RUN_DEBUG;
		if (verbosity > 1)
			flags |= NVMP_RUN_PRSTK;

		if (nvmp_run_all(&vm, &prog, stdin, stdout, stderr, flags) < 0)
			err("error running netvm program\n");

		nvmp_clear(&prog);

	}
	
	return 0;
}
