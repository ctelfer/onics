/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * nvmpf.c -- A NetVM-based packet filter.  Runs netvm_prog.h-format
 *   programs on a packet stream.
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
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include <cat/emalloc.h>
#include "pktbuf.h"
#include "protoparse.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_prog.h"


struct clopt options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"),
	CLOPT_INIT(CLOPT_NOARG, 'e', "--ignore-err", "ignore netvm errors"),
	CLOPT_INIT(CLOPT_NOARG, 'v', "--verbose", "increase verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 'q', "--quiet", "decrease verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 's', "--single_step", "Single step the VM"),
};

struct clopt_parser optparser =
	CLOPTPARSER_INIT(options, array_length(options));


int verbosity = 0;
int ignore_errors = 0;
int single_step = 0;
char *progname;
FILE *infile;
FILE *outfile;

void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: nvmpf [options] progfile [INFILE [OUTFILE]]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s\n", buf);
	exit(1);
}


void parse_options(int argc, char *argv[])
{
	struct clopt *opt;
	int rv;
	infile = stdin;
	outfile = stdout;
	optparse_reset(&optparser, argc, argv);
	while (!(rv = optparse_next(&optparser, &opt))) {
		if (opt->ch == 'h')
			usage();
		else if (opt->ch == 'e')
			ignore_errors = 1;
		else if (opt->ch == 'v')
			++verbosity;
		else if (opt->ch == 'q')
			--verbosity;
		else if (opt->ch == 's')
			single_step = 1;
	}
	if (rv < 0 || rv >= argc || rv < argc - 3)
		usage();

	progname = argv[rv];
	if (rv < argc - 1) {
		infile = fopen(argv[rv+1], "r");
		if (infile == NULL)
			errsys("fopen: ");
	}
	if (rv < argc - 2) {
		outfile = fopen(argv[rv+2], "w");
		if (outfile == NULL)
			errsys("fopen: ");
	}

}


static void initvm(struct netvm *vm, ulong *stk, uint stksz,
		   struct netvm_std_coproc *cproc, struct file_emitter *fe,
		   FILE *dout, struct netvm_program *prog)
{
	int i;
	int rv;
	uint len;
	uint perms;

	netvm_init(vm, stk, stksz);
	if (init_netvm_std_coproc(vm, cproc) < 0)
		errsys("Error initializing NetVM coprocessors: ");

	file_emitter_init(fe, dout);
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
	ulong vmstk[1024];
	struct netvm_std_coproc cproc;
	struct file_emitter fe;
	struct netvm_program prog;
	int rv;
	FILE *pf;
	int flags = 0;

	parse_options(argc, argv);

	register_std_proto();
	pkb_init_pools(1);

	if ((pf = fopen(progname, "r")) == NULL)
		errsys("fopen: ");
	if (nvmp_read(&prog, pf, &rv) < 0)
		err("Error reading netvm program %s: %d\n", progname, rv);
	fclose(pf);

	initvm(&vm, vmstk, array_length(vmstk), &cproc, &fe, stderr, &prog);
	
	if (ignore_errors)
		flags |= NVMP_RUN_IGNORE_ERR;
	if (single_step)
		flags |= NVMP_RUN_SINGLE_STEP;
	if (verbosity > 0)
		flags |= NVMP_RUN_DEBUG;
	if (verbosity > 1)
		flags |= NVMP_RUN_PRSTK;

	return nvmp_run_all(&vm, &prog, infile, outfile, stderr, flags);
}
