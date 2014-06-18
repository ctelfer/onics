/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * rawpkt.c -- generate a raw packet from standard input or a data file
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
#include <cat/optparse.h>
#include "pktbuf.h"


struct clopt g_options[] = {
	CLOPT_I_UINT('d', NULL, "LINKTYPE",
		     "Datalink type of the packet"),
	CLOPT_I_NOARG('h', NULL, "print help")
};

struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));

const char *g_ofname;
FILE *g_infile;
FILE *g_outfile;
uint g_dltype = PRID_RAWPKT;


void usage(const char *prog, const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n%s\n", prog,
		str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	g_infile = stdin;
	g_outfile = stdout;

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(argv[0], NULL);
			break;
		case 'd':
			g_dltype = opt->val.uint_val;
			break;
		}
	}
	if (rv < 0 || rv > argc)
		usage(argv[0], g_oparse.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		g_infile = fopen(fn, "r");
		if (g_infile == NULL)
			errsys("Error opening file %s: ", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		g_outfile = fopen(fn, "w");
		if (g_outfile == NULL)
			errsys("Error opening file %s: ", fn);
	}
}


int main(int argc, char *argv[])
{
	struct pktbuf *pkb;
	size_t nr;

	parse_args(argc, argv);

	pkb_init_pools(1);
	pkb = pkb_create(PKB_MAX_PKTLEN);
	if (pkb == NULL)
		errsys("error allocating packet buffer");

	pkb_set_dltype(pkb, g_dltype);

	nr = fread(pkb_data(pkb), 1, PKB_MAX_PKTLEN, g_infile);
	if (ferror(g_infile))
		errsys("error reading in packet data");

	pkb_set_len(pkb, nr);
	pkb_pack(pkb);

	if (pkb_file_write(pkb, g_outfile) < 0)
		errsys("unable to write out packet");
	pkb_free(pkb);

	return 0;
}
