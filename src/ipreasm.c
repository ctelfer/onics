/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * ipreasm.c -- Reassemble fragmented IPv4 and/or IPv6 packets.
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
#include <cat/optparse.h>
#include <cat/pack.h>
#include <cat/err.h>
#include <cat/hash.h>
#include <cat/cattypes.h>
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "util.h"


/* max of 16 bytes src, 16 bytes dst and 4 bytes ID */
#define FEKSIZE			36
#define FEV4KSIZE		10
#define FEV6KSIZE		36
#define FEPOFF			256
struct fragent {
	struct hnode 		hn;
	byte_t			key[FEKSIZE];
	struct pktbuf *		pkb;
	ulong 			l2hlen;
	ulong 			iphlen;
	ulong			flen;
	int32_t			holes;

};


ONICS_PACK_DECL(
struct fraghole {
	uint16_t		first;
	uint16_t		last;
	int32_t			nhole;
}
);


struct clopt options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_UINT('s', NULL, "TABSIZE",
		     "Size of the fragment hash tables (default: 128)"),
	CLOPT_I_NOARG('4', NULL, "Fragment IPv4 packets (default)"),
	CLOPT_I_NOARG('6', NULL, "Fragment IPv6 packets"),
};
struct clopt_parser oparse =
CLOPTPARSER_INIT(options, array_length(options));

const char *progname;
FILE *infile;
FILE *outfile;
int reasm4 = 0;
int reasm6 = 0;
uint nbkts = 128;
struct htab v4tab;
struct htab v6tab;


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n", progname);
	fprintf(stderr, "Options:\n%s\n", str);
	fprintf(stderr, "\tIf neither '-4' nor '-6' are specified, then\n");
	fprintf(stderr, "\tthe program defaults to '-4'.  The arguments\n");
	fprintf(stderr, "\tcan specify both '-4' and '-6'\n\n");
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	infile = stdin;
	outfile = stdout;
	progname = argv[0];

	optparse_reset(&oparse, argc, argv);
	while (!(rv = optparse_next(&oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
			break;
		case 's':
			nbkts = opt->val.uint_val;
			if (nbkts < 1)
				usage("number of buckets must be > 0");
			break;
		case '4':
			reasm4 = 1;
			break;
		case '6':
			reasm6 = 1;
			break;
		}
	}
	if (rv < 0)
		usage(oparse.errbuf);

	if (reasm4 == 0 && reasm6 == 0)
		reasm4 = 1;

	if (rv < argc) {
		fn = argv[rv++];
		infile = fopen(fn, "r");
		if (infile == NULL)
			errsys("Error opening file %s: ", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		outfile = fopen(fn, "w");
		if (outfile == NULL)
			errsys("Error opening file %s: ", fn);
	}
}


static int fev4kcmp(const void *k1, const void *k2)
{
	return memcmp(k1, k2, FEV4KSIZE);
}


uint khashv4(const void *key, void *unused)
{
	struct raw r = { FEV4KSIZE, (void *)key };
	return ht_rhash(&r, NULL);
}


static int fev6kcmp(const void *k1, const void *k2)
{
	return memcmp(k1, k2, FEV6KSIZE);
}


uint khashv6(const void *key, void *unused)
{
	struct raw r = { FEV6KSIZE, (void *)key };
	return ht_rhash(&r, NULL);
}


void init_tables(void)
{
	struct hnode **nodes;

	nodes = calloc(sizeof(struct list), nbkts);
	if (nodes == NULL)
		errsys("error allocating v4 table: ");
	ht_init(&v4tab, nodes, nbkts, fev4kcmp, khashv4, NULL);

	nodes = calloc(sizeof(struct list), nbkts);
	if (nodes == NULL)
		errsys("error allocating v6 table: ");
	ht_init(&v6tab, nodes, nbkts, fev6kcmp, khashv6, NULL);
}


#define is_v4_frag(fo) ((fo) & (IPH_MFMASK | IPH_FRAGOFFMASK))

static int requires_reassembly(struct pktbuf *p)
{
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv4h *ip;

	if (prp == NULL) {
		return 0;
	} else if (reasm4 && prp->prid == PRID_IPV4) {
		ip = prp_header(prp, p->buf, struct ipv4h);
		return is_v4_frag(ntoh16(ip->fragoff));
	} else if (reasm6 && prp->prid == PRID_IPV6) {
		return prp_off_valid(prp, PRP_IPV6FLD_FRAGH) &&
		       !prp_off_valid(prp, PRP_IPV6FLD_JLEN);
	} else {
		return 0;
	}
}


static struct fraghole *fh_new(byte_t *buf, uint16_t first, uint16_t last,
			       int32_t *holep)
{
	struct fraghole *fh;

	abort_unless(first % 8 == 0);
	abort_unless(last % 8 == 7);
	fh = (struct fraghole *)(buf + first);
	fh->first = first;
	fh->last = last;
	fh->nhole = *holep;
	*holep = first;

	return fh;
}


static struct fragent *fe_alloc(byte_t key[FEKSIZE])
{
	struct fragent *fe;

	fe = malloc(sizeof(*fe));
	if (fe == NULL)
		return NULL;
	fe->pkb = pkb_create(PKB_MAX_PKTLEN);
	if (fe->pkb == NULL) {
		free(fe);
		return NULL;
	}
	ht_ninit(&fe->hn, &fe->key, fe);
	memcpy(fe->key, key, FEKSIZE);
	fe->holes = -1;
	fe->l2hlen = 0;
	fe->iphlen = 0;
	pkb_set_len(fe->pkb, 65535);
	pkb_set_off(fe->pkb, FEPOFF);
	fh_new(fe->pkb->buf + FEPOFF, 0, 65535, &fe->holes);

	return fe;
}


static void fe_free(struct fragent *fe)
{
	ht_rem(&fe->hn);
	if (fe->pkb != NULL)
		pkb_free(fe->pkb);
	free(fe);
}


static void build_v4_key(byte_t key[FEKSIZE], struct prparse *prp, byte_t *buf)
{
	struct ipv4h *ip = prp_header(prp, buf, struct ipv4h);
	memset(key, 0, FEKSIZE);
	memcpy(key, &ip->saddr, 4);
	memcpy(key+4, &ip->daddr, 4);
	memcpy(key+8, &ip->id, 2);
}


static void build_v6_key(byte_t key[FEKSIZE], struct prparse *prp, byte_t *buf)
{
	struct ipv6h *ip6 = prp_header(prp, buf, struct ipv6h);
	struct ipv6_fragh *v6fh = 
		(struct ipv6_fragh *)(buf + prp->offs[PRP_IPV6FLD_FRAGH]);
	memset(key, 0, FEKSIZE);
	memcpy(key, &ip6->saddr, 16);
	memcpy(key+16, &ip6->daddr, 16);
	memcpy(key+32, &v6fh->id, 4);
}


static struct fragent *fe_lkup(struct pktbuf *p)
{
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	byte_t key[FEKSIZE];
	struct hnode *hn;
	struct fragent *fe;
	uint h;

	if (prp->prid == PRID_IPV4) {
		build_v4_key(key, prp, p->buf);
		hn = ht_lkup(&v4tab, key, &h);
		if (hn != NULL) {
			fe = hn->data;
		} else {
			fe = fe_alloc(key);
			if (fe == NULL)
				return fe;
			ht_ins(&v4tab, &fe->hn, h);
		}
	} else {
		abort_unless(prp->prid == PRID_IPV6);
		build_v6_key(key, prp, p->buf);
		hn = ht_lkup(&v6tab, key, &h);
		if (hn != NULL) {
			fe = hn->data;
		} else {
			fe = fe_alloc(key);
			if (fe == NULL)
				return fe;
			ht_ins(&v6tab, &fe->hn, h);
		}
	}

	return fe;
}


static void fill_hole(struct fraghole *fh, byte_t *db, ulong first,
		      ulong last, byte_t *sb)
{
	if (first < fh->first) {
		sb += fh->first - first;
		first = fh->first;
	} else if (first > fh->first) {
		db += first - fh->first;
	}

	if (last > fh->last)
		last = fh->last;

	memcpy(db, sb, last - first + 1);
}


static int fe_add_frag(struct fragent *fe, byte_t *bp, uint16_t first,
		       uint16_t last, int islast)
{
	int32_t *hole;
	struct fraghole *fh, fh0;
	struct pktbuf *fp = fe->pkb;

	hole = &fe->holes;
	while (*hole >= 0) {
		fh = (struct fraghole *)(fp->buf + FEPOFF + *hole);

		if (first > fh->last) {
			hole = &fh->nhole;
			continue;
		}

		if (last < fh->first)
			break;

		/* we have overlap:  save the fraghole and delete it */
		fh0 = *fh;
		*hole = fh0.nhole;

		fill_hole(&fh0, (byte_t *)fh, first, last, bp);

		if (fh0.first < first) {
			fh = fh_new(fp->buf + FEPOFF, fh0.first, first-1,
				    hole);
			hole = &fh->nhole;
		}

		if (last < fh0.last) {
			if (!islast)  {
				fh = fh_new(fp->buf + FEPOFF, last + 1, 
					    fh0.last, hole);
				hole = &fh->nhole;
			} else {
				fe->flen = last + 1;
				if (fe->flen + first > 65535)
					return -1;
			}
		}
	}

	return 0;
}


int fe_add_v4_frag(struct fragent *fe, struct pktbuf *p)
{
	struct pktbuf *fp = fe->pkb;
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv4h *ip = prp_header(prp, p->buf, struct ipv4h);
	ulong first;
	ulong last;
	int islast;

	first = ntoh16(ip->fragoff);
	islast = (first & IPH_MFMASK) == 0;
	first = (first & IPH_FRAGOFFMASK) * 8;
	last = first + prp_plen(prp) - 1;

	if (last > 65535)
		return -1;

	if (first == 0) {
		fe->iphlen = IPH_HLEN(*ip);
		fe->l2hlen = prp_soff(prp) - pkb_get_off(p);
		if (fe->iphlen + fe->l2hlen > FEPOFF)
			return -1;
		pkb_set_off(fp, FEPOFF - (fe->iphlen + fe->l2hlen));
		memcpy(pkb_data(fp), pkb_data(p), fe->iphlen + fe->l2hlen);
		pkb_set_dltype(fp, pkb_get_dltype(p));
	}

	if (fe_add_frag(fe, prp_payload(prp, p->buf), first, last, islast) < 0)
		return -1;

	if (fe->holes == -1) {
		if (fe->flen + fe->iphlen > 65535)
			return -1;
		/* fix up IP header:  length, fragoff, checksum */
		pkb_set_len(fp, fe->l2hlen + fe->iphlen + fe->flen);
		ip = (struct ipv4h *)(pkb_data(fp) + fe->l2hlen);
		ip->len = hton16(fe->iphlen + fe->flen);
		ip->fragoff = 0;
		ip->cksum = 0;
		ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
		return 1;
	} else {
		return 0;
	}
	
}


static int reassemble_v4(struct pktbuf **pp)
{
	struct pktbuf *p = *pp;
	struct fragent *fe;
	int rv;

	fe = fe_lkup(p);
	if (fe == NULL)
		return -1;

	rv = fe_add_v4_frag(fe, p);
	pkb_free(p);
	if (rv < 0) {
		fe_free(fe);
	} else if (rv > 0) {
		*pp = fe->pkb;
		fe->pkb = NULL;
		fe_free(fe);
	}

	return rv;
}


int fe_add_v6_frag(struct fragent *fe, struct pktbuf *p)
{
	struct pktbuf *fp = fe->pkb;
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv6_fragh *fh;
	struct ipv6h *ip6;
	ulong first;
	ulong last;
	int islast;
	byte_t *fragp, *prevp;

	abort_unless(prp_off_valid(prp, PRP_IPV6FLD_FRAGH));
	fh = (struct ipv6_fragh *)(p->buf + prp->offs[PRP_IPV6FLD_FRAGH]);

	first = ntoh16(fh->fragoff);
	islast = (first & IPV6_FRAGH_MFMASK) == 0;
	first &= IPV6_FRAGH_FOMASK;
	abort_unless(prp_toff(prp) > prp->offs[PRP_IPV6FLD_FRAGH] + 8);
	last = first + prp_toff(prp) - (prp->offs[PRP_IPV6FLD_FRAGH] + 8) - 1;

	if (last > 65535)
		return -1;

	if (first == 0) {
		fe->iphlen = prp->offs[PRP_IPV6FLD_FRAGH] - prp_soff(prp);
		fe->l2hlen = prp_soff(prp) - pkb_get_off(p);
		if (fe->iphlen + fe->l2hlen > FEPOFF)
			return -1;
		pkb_set_off(fp, FEPOFF - (fe->iphlen + fe->l2hlen));
		memcpy(pkb_data(fp), pkb_data(p), fe->iphlen + fe->l2hlen);
		fragp = ip6findh(pkb_data(fp) + fe->l2hlen, fe->iphlen,
				 IPPROT_V6_FRAG_HDR, &prevp);
		abort_unless(fragp != NULL);
		*prevp = fh->nxthdr;
		pkb_set_dltype(fp, pkb_get_dltype(p));
	}

	if (fe_add_frag(fe, (((byte_t *)fh) + 8), first, last, islast) < 0)
		return -1;

	if (fe->holes == -1) {
		pkb_set_len(fp, fe->l2hlen + fe->iphlen + fe->flen);
		ip6 = (struct ipv6h *)(pkb_data(fp) + fe->l2hlen);
		ip6->len = hton16(fe->iphlen - IPV6H_LEN + fe->flen);
		return 1;
	} else {
		return 0;
	}
}


static int reassemble_v6(struct pktbuf **pp)
{
	struct pktbuf *p = *pp;
	struct fragent *fe;
	int rv;

	fe = fe_lkup(p);
	if (fe == NULL)
		return -1;

	rv = fe_add_v6_frag(fe, p);
	pkb_free(p);
	if (rv < 0) {
		fe_free(fe);
	} else if (rv > 0) {
		*pp = fe->pkb;
		fe->pkb = NULL;
		fe_free(fe);
	}

	return rv;
}


static int reassemble(struct pktbuf **pp)
{
	struct prparse *prp = (*pp)->layers[PKB_LAYER_NET];
	abort_unless(prp != NULL);
	if (prp->prid == PRID_IPV4) {
		return reassemble_v4(pp);
	} else {
		abort_unless(prp->prid == PRID_IPV6);
		return reassemble_v6(pp);
	} 
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *p;
	ulong pn = 0;

	pkb_init_pools(128);
	register_std_proto();
	parse_args(argc, argv);
	init_tables();

	while ((rv = pkb_file_read_a(&p, infile, NULL, NULL)) > 0) {
		++pn;
		if (pkb_parse(p) < 0)
			err("Error parsing packet %lu\n", pn);

		if (requires_reassembly(p)) {
			if (reassemble(&p) == 0)
				continue;
		}

		pkb_pack(p);
		if (pkb_file_write(p, outfile) < 0)
			errsys("pkb_file_write(): ");
	}
	if (rv < 0)
		errsys("pkb_file_read_a(): ");

	return 0;
}
