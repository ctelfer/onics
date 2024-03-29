/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * pml_main.c -- Main file for the PML programming language/utility.
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
#include "prload.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_prog.h"
#include "pmllex.h"
#include "pmltree.h"
#include "pmlncg.h"


#define STDLIB_FILENAME "std.pml"
#define PML_SYS_PATH	ONICS_INSTALL_PREFIX "/lib/pml"

struct clopt options[] = {
	CLOPT_I_STRING('c', NULL, "BINFILE",
		       "compile to netvm program file"),
	CLOPT_I_STRING('e', NULL, "EXPR", "input expression"),
	CLOPT_I_NOARG('E', NULL, "ignore netvm errors"),
	CLOPT_I_STRING('f', NULL, "INFILE", "input PML program"),
	CLOPT_I_NOARG('h', NULL, "print help and exit"),
	CLOPT_I_NOARG('i', NULL, "import standard library by default"),
	CLOPT_I_STRING('I', NULL, "DIR",
			"append directory to import search path"),
	CLOPT_I_NOARG('P', NULL, "remove system path from import sarch path"),
	CLOPT_I_NOARG('q', NULL, "decrease verbosity"),
	CLOPT_I_NOARG('s', NULL, "single step the program"),
	CLOPT_I_NOARG('v', NULL, "increase verbosity"),
};

struct clopt_parser optparser =
	CLOPTPARSER_INIT(options, array_length(options));


enum {
	I_FILE,
	I_STR,
};

struct pmlinput {
	int			type;
	const char *		str;
};

int verbosity = 0;
int ignore_errors = 0;
int single_step = 0;
int include_system_path = 1;
int import_std_lib = 0;
char *progname;
const char *ofname = NULL;
char ipath[512] = "";


#define MAXINPUT	64
struct pmlinput isrc[MAXINPUT];
int nisrc = 0;
int iidx = 0;
int insnum = 0;


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: pml [options] [INFILE [OUTFILE]]\n");
	fprintf(stderr, "       pml [-e EXPR|-f PROGFILE ...] [-c NVMPFILE]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s\n", buf);
	exit(1);
}


void pmleoi(struct pmllex *scanner)
{
	struct pmlinput *pi;
	static char insname[64];
	FILE *infile;

	if (iidx == nisrc)
		return;

	pi = &isrc[iidx++];
	if (pi->type == I_FILE) {
		infile = fopen(pi->str, "r");
		if (!infile)
			errsys("Error opening file '%s'\n", pi->str);
		if (pmll_add_infile(scanner, infile, 0, pi->str) < 0)
			errsys("Error adding input file '%s'\n", pi->str);
	} else {
		++insnum;
		snprintf(insname, sizeof(insname), "-expr%d-", insnum);
		if (pmll_add_instr(scanner, pi->str, 0, insname) < 0)
			errsys("Error adding expression '%d'\n", insnum);
	}
}


void add_isrc(const char *s, int type)
{
	if (nisrc == MAXINPUT)
		err("Error: too many input sources.  Max set to %d\n",
		    MAXINPUT);

	isrc[nisrc].str = s;
	isrc[nisrc].type = type;
	++nisrc;
}


static void append_import_path(const char *dir)
{
	if (ipath[0] != '\0')
		str_cat(ipath, ":", sizeof(ipath));
	if (str_cat(ipath, dir, sizeof(ipath)) >= sizeof(ipath))
		err("Import path is too long.\n");
}


void parse_options(int argc, char *argv[], FILE **fin, FILE **fout)
{
	struct clopt *opt;
	int rv;
	const char *fn;

	optparse_reset(&optparser, argc, argv);
	while (!(rv = optparse_next(&optparser, &opt))) {
		if (opt->ch == 'c') {
			ofname = opt->val.str_val;
		} else if (opt->ch == 'e') {
			add_isrc(opt->val.str_val, I_STR);
		} else if (opt->ch == 'E') {
			ignore_errors = 1;
		} else if (opt->ch == 'f') {
			add_isrc(opt->val.str_val, I_FILE);
		} else if (opt->ch == 'h') {
			usage();
		} else if (opt->ch == 'i') {
			import_std_lib = 1;
		} else if (opt->ch == 'I') {
			append_import_path(opt->val.str_val);
		} else if (opt->ch == 'P') {
			include_system_path = 0;
		} else if (opt->ch == 'q') {
			--verbosity;
		} else if (opt->ch == 's') {
			single_step = 1;
	        } else if (opt->ch == 'v') {
			++verbosity;
		}
	}

	if (rv < argc - 2)
		usage();

	if (rv < argc) {
		if (ofname != NULL)
			usage();

		fn = argv[rv++];
		*fin = fopen(fn, "r");
		if (*fin == NULL)
			errsys("fopen(\"%s\", \"r\"): ", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		*fout = fopen(fn, "w");
		if (*fout == NULL)
			errsys("fopen(\"%s\", \"w\"): ", fn);
	}
}


void parse_pml_program(struct netvm_program *prog)
{
	int tok;
	struct pmllex *scanner;
	pml_parser_t parser;
	struct pml_ast ast;
	struct pmll_val extra;
	char estr[PMLNCG_MAXERR];

	if ((scanner = pmll_alloc()) == NULL)
		errsys("pmllex_init: ");
	if (ipath[0] != '\0')
		if (pmll_ipath_append(scanner, ipath) < 0)
			err("Import path too long");
	if (include_system_path)
		if (pmll_ipath_append(scanner, PML_SYS_PATH) < 0)
			err("Import path too long");
	if (import_std_lib)
		if (pmll_open_add_infile(scanner, STDLIB_FILENAME, 1) < 0)
			errsys("Unable to open %s: ", STDLIB_FILENAME);
	pmll_set_eoicb(scanner, &pmleoi);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc: ");
	if (pml_ast_init(&ast) < 0)
		errsys("pml_ast_init(): ");
	pml_ast_set_parser(&ast, scanner, parser);
	if (pml_ast_add_std_intrinsics(&ast) < 0)
		errsys("pml_ast_add_std_intrinsics(): ");

	if (verbosity > 0)
		fprintf(stderr, "Starting program parse\n");

	do {
		tok = pmll_nexttok(scanner, &extra);
		if (tok < 0)
			err("Syntax error on line %lu of %s: '%s'\n",
			    pmll_get_lineno(scanner),
			    pmll_get_iname(scanner),
			    pmll_get_err(scanner));
		if (pml_parse(parser, &ast, tok, extra)) {
			err("parse error on line %lu of %s: %s\n",
			    pmll_get_lineno(scanner),
			    pmll_get_iname(scanner),
			    ast.errbuf);
		}
	} while (tok > 0);

	if (!ast.done)
		err("Program file is not a complete PML program\n");

	pml_ast_free_parser(&ast);

	/* TODO: modify pml_ast_print() to take a file to print to files */

	if (verbosity > 0)
		fprintf(stderr, "done parsing:  optimizing the program\n");

	if (pml_ast_optimize(&ast) < 0)
		err("Error optimizing PML tree: %s\n", ast.errbuf);

	nvmp_init(prog);
	if (pml_to_nvmp(&ast, prog, 0, estr) < 0)
		err("Error generating code in pml_to_nvmp:\n%s", estr);
}


void initvm(struct netvm *vm, ulong *stk, uint stksz,
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


void finivm(struct netvm *vm, struct netvm_std_coproc *cproc,
	    struct netvm_program *prog)
{
	int i;
	nvmp_clear(prog);
	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		free(vm->msegs[i].base);
		vm->msegs[i].base = NULL;
	}
	fini_netvm_std_coproc(cproc);
}


int main(int argc, char *argv[])
{
	struct netvm vm;
	ulong vmstk[1024];
	struct netvm_std_coproc cproc;
	struct file_emitter fe;
	struct netvm_program prog;
	FILE *infile = stdin;
	FILE *outfile = stdout;
	int flags = 0;
	int rv;

	parse_options(argc, argv, &infile, &outfile);

	if (nisrc == 0)
		err("No program sources provided: use -f or -e\n");

	register_std_proto();
	load_external_protocols();
	pkb_init_pools(1);

	parse_pml_program(&prog);

	if (ofname != NULL) {

		if ((outfile = fopen(ofname, "w")) == NULL)
			errsys("error opening output file '%s': ", ofname);
		if (nvmp_write(&prog, outfile) < 0)
			errsys("error writing out program: ");
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

		rv = nvmp_run_all(&vm, &prog, infile, outfile, stderr, flags);
		if (rv < 0)
			err("error running netvm program: %s\n",
			    netvm_estr(vm.status));

		finivm(&vm, &cproc, &prog);
	}

	pkb_free_pools();
	fclose(outfile);
	fclose(infile);

	return 0;
}
