/*
 * ONICS
 * Copyright 2021
 * Christopher Adam Telfer
 *
 * tcpcarve.c -- Extract application data from a stream of TCP packets
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
#include <errno.h>
#include <cat/cat.h>
#include <cat/err.h>
#include <cat/list.h>
#include <cat/optparse.h>
#include <cat/pack.h>
#include <cat/str.h>
#include "pktbuf.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"


#define MAXFNAME 65536
const char *prefix = "data.";
const char *progname;
int quiet = 0;
FILE *infile;

struct clopt options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_STRING('p', NULL, "PREFIX",
		       "Prefix to use for each file"),
	CLOPT_I_NOARG('q', NULL,
		      "Suppress warnings for missing data or non-TCP packets"),
};
struct clopt_parser oparse =
CLOPTPARSER_INIT(options, array_length(options));


enum {
	INVALID = -1,
	C2S = 0,
	S2C = 1,
};


union addr {
	uint32_t		ip;
	struct ipv6addr		ip6;
};

struct conn_tuple {
	union addr saddr;
	union addr daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t netproto;
};

struct tcp_state {
	int seen;
	int dir;
	uint32_t nxtseq;
	int npending;
	struct list pending;
};


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE]\nOptions:\n%s\n",
		progname, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	infile = stdin;
	progname = argv[0];

	optparse_reset(&oparse, argc, argv);
	while (!(rv = optparse_next(&oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
			break;
		case 'p':
			prefix = opt->val.str_val;
			break;
		case 'q':
			quiet = 1;
			break;
		}
	}
	if (rv < 0)
		usage(oparse.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		infile = fopen(fn, "r");
		if (infile == NULL)
			errsys("Error opening file %s: ", fn);
	}
}


int get_tcp(struct pktbuf *p, struct pdu **pdu, struct tcph **tcp)
{
	*pdu = NULL;
	*tcp = NULL;
	if ((*pdu = p->layers[PKB_LAYER_XPORT]) == NULL)
		return -1;
	if ((*pdu)->prid != PRID_TCP)
		return -1;
	*tcp = pdu_header(*pdu, p->buf, struct tcph);
	return 0;
}


void Get_tcp(struct pktbuf *p, struct pdu **pdu, struct tcph **tcp)
{
	int rv = get_tcp(p, pdu, tcp);
	abort_unless(rv >= 0);
}


void tcp_state_init(struct tcp_state *ts)
{
	memset(ts, 0, sizeof(*ts));
	l_init(&ts->pending);
}


#define le2pkb(le) container((le), struct pktbuf, entry)

int32_t seq_cmp(uint32_t s1, uint32_t s2)
{
	return (int32_t)(s1 - s2);
}

void tcp_state_enqueue(struct tcp_state *ts, struct pktbuf *p)
{
	struct pdu *pdu;
	struct tcph *tcp;
	struct pdu *pdu2;
	struct tcph *tcp2;
	struct list *node, *xnode;
	int32_t n;

	Get_tcp(p, &pdu, &tcp);
	l_for_each_safe(node, xnode, &ts->pending) {
		Get_tcp(le2pkb(node), &pdu2, &tcp2);
		n = seq_cmp(ntoh32(tcp->seqn), ntoh32(tcp2->seqn));
		if (n == 0) {
			pkb_free(p);
			return;
		}
		if (n > 0) {
			++ts->npending;
			l_ins(node, &p->entry);
			return;
		}
	}
	++ts->npending;
	l_enq(&ts->pending, &p->entry);
}


void tcp_state_write_pending(FILE *outfile, struct tcp_state *ts)
{
	struct pktbuf *p;
	struct pdu *pdu;
	struct tcph *tcp;
	int32_t n;
	uint32_t start;
	uint32_t end;
	uint32_t off;
	uint32_t len;
	byte_t *data;
	size_t nw;

	while (!l_isempty(&ts->pending)) {
		p = le2pkb(l_head(&ts->pending));
		Get_tcp(p, &pdu, &tcp);
		start = ntoh32(tcp->seqn);
		n = seq_cmp(ts->nxtseq, start);
		if (n < 0)
			return;

		l_rem(&p->entry);
		end = start + pdu_plen(pdu);
		if (n > 0) {
			n = seq_cmp(ts->nxtseq, end);
			if (n >= 0) {
				pkb_free(p);
				continue;
			}
			off = ts->nxtseq - start;
			data = pdu_payload(pdu, p->buf) + off;
			len = pdu_plen(pdu) - off;
		} else {
			data = pdu_payload(pdu, p->buf);
			len = pdu_plen(pdu);
		}

		nw = fwrite(data, 1, len, outfile);
		if (nw < len)
			errsys("fwrite(): ");
		pkb_free(p);
		ts->nxtseq += len;
	}
}


int extract_tuple(struct pktbuf *p, struct conn_tuple *t)
{
	struct pdu *pdu;
	struct ipv4h *ip;
	struct ipv6h *ip6;
	struct tcph *tcp;

	memset(t, 0, sizeof(*t));
	if ((pdu = p->layers[PKB_LAYER_NET]) == NULL)
		return -1;
	t->netproto = pdu->prid;
	if (pdu->prid == PRID_IPV4) {
		ip = pdu_header(pdu, p->buf, struct ipv4h);
		t->saddr.ip = ip->saddr;
		t->daddr.ip = ip->daddr;
	} else if (pdu->prid == PRID_IPV6) {
		ip6 = pdu_header(pdu, p->buf, struct ipv6h);
		t->saddr.ip6 = ip6->saddr;
		t->daddr.ip6 = ip6->daddr;
	} else {
		return -1;
	}

	if ((pdu = p->layers[PKB_LAYER_XPORT]) == NULL)
		return -1;
	if (pdu->prid != PRID_TCP)
		return -1;
	tcp = pdu_header(pdu, p->buf, struct tcph);
	if (get_tcp(p, &pdu, &tcp) < 0)
		return -1;
	t->sport = tcp->sport;
	t->dport = tcp->dport;

	return 0;
}


int tuple_match(struct conn_tuple *ct, struct conn_tuple *pt)
{
	struct conn_tuple rt = {0};
	if (memcmp(ct, pt, sizeof(*ct)) == 0)
		return C2S;
	rt.saddr = pt->daddr;
	rt.daddr = pt->saddr;
	rt.sport = pt->dport;
	rt.dport = pt->sport;
	rt.netproto = pt->netproto;
	if (memcmp(ct, &rt, sizeof(*ct)) == 0)
		return S2C;
	return INVALID;
}


FILE *open_outfile(ulong nfiles, int dir)
{
	char ofname[MAXFNAME];
	int rv;
	char *sfx = (dir == C2S) ? ".c2s" : ".s2c";
	FILE *of;

	rv = str_fmt(ofname, sizeof(ofname), "%s%04lu%s", prefix, nfiles, sfx);
	if (rv < 0 || rv >= MAXFNAME)
		err("filename too long!");

	of = fopen(ofname, "w");
	if (of == NULL)
		errsys("fopen(\"%s\", \"w\"): ", ofname);
	return of;
}


/* Write 0xdb through to next packet and flush contiguous packets from there */
void flush_next_pending(FILE *outfile, struct tcp_state *ts)
{
	struct pktbuf *p = le2pkb(l_head(&ts->pending));
	struct pdu *pdu;
	struct tcph *tcp;
	uint32_t start;
	uint32_t len;
	size_t wlen;
	int nw = 0;
	byte_t buf[4096];

	Get_tcp(p, &pdu, &tcp);
	start = ntoh32(tcp->seqn);
	abort_unless(seq_cmp(ts->nxtseq, start) < 0);
	len = start - ts->nxtseq;
	memset(buf, 0xdb, sizeof(buf));
	while (len > 0) {
		wlen = len > sizeof(buf) ? sizeof(buf) : len;
		nw = fwrite(buf, 1, wlen, outfile);
		if (nw < wlen)
			errsys("fwrite(): ");
		len -= nw;
		ts->nxtseq += nw;
	}

	tcp_state_write_pending(outfile, ts);
}


/* flush out through all enqueued packets */
void flush_outfile(FILE *outfile, struct tcp_state *ts)
{
	while (!l_isempty(&ts->pending))
		flush_next_pending(outfile, ts);
	fclose(outfile);
}


void extract_data(FILE *outfile, struct pktbuf *p, struct tcp_state *ts)
{
	tcp_state_enqueue(ts, p);
	tcp_state_write_pending(outfile, ts);
}


void carve_app_data()
{
	FILE *outfile = NULL;
	struct tcp_state c2s;
	struct tcp_state s2c;
	struct tcp_state *ts;
	int fdir = INVALID;
	int pdir;
	int rv;
	struct pktbuf *p;
	struct conn_tuple conntuple;
	struct conn_tuple pkttuple;
	struct pdu *pdu;
	struct tcph *tcp;
	ulong pn = 0;
	ulong nfiles = 0;

	tcp_state_init(&c2s);
	tcp_state_init(&s2c);

	/* Find the first packet of the flow */
	while (1) {
		rv = pkb_file_read_a(&p, infile, NULL, NULL);
		if (rv < 0)
			errsys("pkb_file_read_a() of packet %lu: ", pn);
		if (rv == 0)
			return;
		++pn;
		if (pkb_parse(p) == 0 && extract_tuple(p, &conntuple) >= 0)
			break;
		if (!quiet)
			fprintf(stderr,
				"Packet %lu is not a TCP packet (skipping)\n",
				pn);
		pkb_free(p);
	}

	Get_tcp(p, &pdu, &tcp);
	if (!(tcp->flags & TCPF_SYN) || (tcp->flags & TCPF_ACK)) {
		if (!quiet)
			fprintf(stderr, "Warning: first packet is not a SYN\n");
	}
	pkb_clear_parse(p);

	--pn;
	do {
		++pn;
		if (pkb_parse(p) < 0 || extract_tuple(p, &pkttuple) < 0) {
			if (!quiet)
				fprintf(stderr,
					"Packet %lu is not a TCP packet "
					"(skipping)\n", pn);
			pkb_free(p);
			continue;
		}

		pdir = tuple_match(&conntuple, &pkttuple);
		if (pdir == INVALID) {
			if (!quiet)
				fprintf(stderr,
					"Packet %lu is from a different "
					"connection skipping)\n", pn);
			pkb_free(p);
			continue;
		}

		Get_tcp(p, &pdu, &tcp);

		ts = (pdir == C2S) ? &c2s : &s2c;
		if (!ts->seen) {
			ts->seen = 1;
			ts->nxtseq = ntoh32(tcp->seqn) + 1;
			if (!(tcp->flags & TCPF_SYN)) {
				if (!quiet) {
					char *origin = pdir == C2S 
						? "client" 
						: "server";
					fprintf(stderr, 
						"Warning: first packet from %s"
					        "is not a SYN\n", origin);
				}
				--ts->nxtseq;
			}
		}
		if (pdu_plen(pdu) <= 0) {
			pkb_free(p);
			continue;
		}
		if (!(tcp->flags & TCPF_ACK)) {
			if (!quiet)
				fprintf(stderr,
					"Data packet %lu has no ACK flag"
					"(skipping)\n", pn);
			pkb_free(p);
			continue;
		}


		if (pdir != fdir) {
			if (outfile != NULL) {
				ts = (fdir == C2S) ? &c2s : &s2c;
				flush_outfile(outfile, ts);
				outfile = NULL;
			}
			fdir = pdir;
			outfile = open_outfile(nfiles, fdir);
			++nfiles;
		}

		ts = (pdir == C2S) ? &c2s : &s2c;
		abort_unless(ts->seen);

		/* extract_data() will free the packet buffer or enqueue it */
		extract_data(outfile, p, ts);

	} while ((rv = pkb_file_read_a(&p, infile, NULL, NULL)) > 0);
	if (rv < 0)
		errsys("pkb_file_read_a() of packet %lu: ", pn);

	if (outfile != NULL) {
		ts = (fdir == C2S) ? &c2s : &s2c;
		flush_outfile(outfile, ts);
	}
}


int main(int argc, char *argv[])
{
	register_std_proto();
	pkb_init_pools(1);
	parse_args(argc, argv);
	carve_app_data();
	return 0;
}
