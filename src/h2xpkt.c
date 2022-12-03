/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * h2xpkt.c -- Convert a hexpkt stream of packets to an xpkt stream of
 *   packets.
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
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <cat/err.h>
#include <cat/str.h>
#include <cat/optparse.h>
#include "pktbuf.h"
#include "xpkt.h"
#include "ns.h"
#include "stdproto.h"
#include "prload.h"

#define MAXLINE 256

uint g_dlt = PRID_INVALID;
ulong g_lineno = 0;
ulong g_pktno = 1;
int g_toolong = 0;
int g_do_flush = 0;
int g_strict_addr = 0;
FILE *infile;
FILE *outfile;

struct clopt g_optarr[] = {
	CLOPT_I_STRING('l', NULL, "LINKTYPE",
		       "no xpkt header: each packet starts with type <x>"),
	CLOPT_I_NOARG('f', NULL, "Flush output per packet"),
	CLOPT_I_NOARG('s', NULL, "Strict address format"),
	CLOPT_I_NOARG('h', NULL, "print help")
};

struct clopt_parser g_oparser =
	CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));



void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n",
		g_oparser.argv[0]);
	fprintf(stderr, "%s\n", ubuf);
	exit(1);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	const char *s;
	struct ns_elem *e;
	infile = stdin;
	outfile = stdout;
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'l':
			s = opt->val.str_val;
			if (strncmp(s, "0x", 2) == 0) {
				g_dlt = strtoul(s + 2, NULL, 16);
			} else {
				e = ns_lookup(NULL, s);
				if (e == NULL || e->type != NST_NAMESPACE)
					err("Unknown protocol '%s'", s);
				g_dlt = ((struct ns_namespace *)e)->prid;
			}
			break;
		case 'f':
			g_do_flush = 1;
			break;
		case 's':
			g_strict_addr = 1;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (rv < g_oparser.argc - 2)
		usage(NULL);

	if (rv < g_oparser.argc) {
		if (strcmp(g_oparser.argv[rv], "-") == 0)
			infile = stdin;
		else if ((infile = fopen(g_oparser.argv[rv], "r")) == NULL)
			errsys("fopen: ");
	}
	if (rv < g_oparser.argc-1) {
		if ((outfile = fopen(g_oparser.argv[rv+1], "w")) == NULL)
			errsys("fopen: ");
	}
}


int readline(char *cp, size_t len)
{
	int ch = EOF;
	char *save = cp;

	g_lineno += 1;
	g_toolong = 0;

	while (len > 1) {
		ch = fgetc(infile);
		if (ch == EOF)
			break;
		if (!isprint(ch) && (ch != '\n') && (ch != '\t'))
			err("invalid character (%d) on line %lu\n", ch,
			    g_lineno);
		if (ch == '\n')
			break;
		*cp++ = ch;
		len -= 1;
	}

	*cp = '\0';
	if (ch == EOF) {
		if (cp == save)
			return 0;
	} else if (ch != '\n') {
		fprintf(stderr, "WARNING: line %lu is too long.  "
				"Trailing data will lbe ignored\n", g_lineno);
		g_toolong = 1;
	}

	return 1;
}


void clearline()
{
	int v;
	do {
		v = fgetc(infile);
	} while ((v != EOF) && (v != '\n'));
}


char *skipspace(char *str)
{
	str += strspn(str, " \t");
	if (strncmp(str, "0x", 2) == 0)
		str += 2;
	return str;
}


void write_packet(struct pktbuf *pkb)
{
	ulong nb = pkb_get_off(pkb);
	ulong xlen;
	struct xpkt *x;
	int rv;

	if (g_dlt == PRID_INVALID) {
		if (nb < XPKT_HLEN)
			err("Packet %lu is a runt", g_pktno);
		x = (struct xpkt *)pkb->buf;
		xpkt_unpack_hdr(&x->hdr);
		if ((rv = xpkt_validate_hdr(&x->hdr)) < 0)
			err("Packet %lu has an invalid xpkt header: %d\n",
			    g_pktno, rv);
		if (x->hdr.len != nb)
			err("Packet %lu's xpkt length doesn't match bytes read"
			    ": header val = %lu, bytes read = %lu\n",
			    g_pktno, x->hdr.len, nb);
		if ((rv = xpkt_unpack_tags(x->tags, x->hdr.tlen)) < 0)
			err("Error unpacking tags in packet %lu: %d\n",
			    g_pktno, rv);
		if ((rv = xpkt_validate_tags(x->tags, x->hdr.tlen)) < 0)
			err("Error validating tags in packet %lu: %d\n",
			    g_pktno, rv);
		xlen = xpkt_doff(x);
		if (xlen > pkb->xsize)
			err("xpkt header too large for packet %lu buffer\n",
			    g_pktno);
		memmove(pkb_get_xpkt(pkb), pkb->buf, xlen);
		pkb_set_off(pkb, xlen);
		pkb_set_len(pkb, xpkt_data_len(x));
	} else {
		pkb_set_off(pkb, 0);
		pkb_set_len(pkb, nb);
		pkb_set_dltype(pkb, g_dlt);
	}

	if (pkb_pack(pkb) < 0)
		err("Error packing packet\n");
	if (pkb_file_write(pkb, outfile))
		errsys("Error sending packet\n");
	if (g_do_flush)
		fflush(outfile);

	pkb_reset(pkb);
	pkb_set_len(pkb, 0);
}


void scan_bytes(char *cp, struct pktbuf *pkb)
{
	byte_t *dp, *save;
	size_t nb;
	ulong off;

	/* using the data offset to save the current pointer to add data */
	save = dp = pkb_data(pkb);
	cp = skipspace(cp);
	off = pkb_get_off(pkb);
	nb = pkb_get_bufsize(pkb) - off;

	while (isxdigit(cp[0])) {
		if (!isxdigit(cp[1]))
			err("unpaired nibble on line %lu\n", g_lineno);
		if (nb == 0)
			err("Out of buffer space for packet %lu\n", g_pktno);
		*dp++ = chnval(cp[0]) * 16 + chnval(cp[1]);
		--nb;
		cp = skipspace(cp + 2);
	}

	pkb_set_off(pkb, (dp - save) + off);
}


int main(int argc, char *argv[])
{
	char *cp, *end;
	char line[MAXLINE];
	struct pktbuf *pkb = NULL;
	ulong off;

	register_std_proto();
	load_external_protocols();
	optparse_reset(&g_oparser, argc, argv);
	parse_options();
	pkb_init_pools(1);
	if ((pkb = pkb_create(PKB_MAX_PKTLEN)) == NULL)
		errsys("unable to create packet: ");
	pkb_set_off(pkb, 0);
	pkb_set_len(pkb, 0);

	while (readline(line, sizeof(line))) {

		cp = skipspace(line);

		if (*cp == '\0') {
			if (pkb_get_off(pkb) > 0) {
				write_packet(pkb);
				g_pktno++;
			}
			if (g_toolong)
				clearline();
			continue;
		}

		if (*cp == '#') {
			if (g_toolong)
				clearline();
			continue;
		}

		off = strtoul(cp, &end, 16);
		if (*end == ':') {
			if (g_strict_addr && off != pkb_get_off(pkb))
				err("Invalid address at line %lu:"
				    " expected %lu but got %lu\n", g_lineno,
				    pkb_get_off(pkb), off);
			cp = end + 1;
		} else if (g_strict_addr) {
			err("Invalid address format on line %lu\n", g_lineno);
		}

		scan_bytes(cp, pkb);
	}

	if (pkb_get_off(pkb) != 0)
		write_packet(pkb);

	pkb_free(pkb);

	return 0;
}
