/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * psort.c -- Sort a set of packets according to a user specified key.
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
#include <cat/list.h>
#include <cat/optparse.h>
#include <cat/err.h>
#include <cat/pack.h>
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"
#include "fld.h"


enum {
	KF_XPKT,
	KF_NSPF,
};

struct kfxpkt {
	int type;
	const char *name;
	int tagtype;
	int aisub;
};

struct kfnspf {
	int type;
	const char *name;
	int idx;
	struct ns_pktfld *pf;
};

union keyfield {
	int		type;
	struct kfxpkt	xpkt;
	struct kfnspf	nspf;
};


int numkf = 0;
union keyfield keyfields[256];
FILE *infile;
FILE *outfile;
const char *progname;
int reverse = 0;
ulong keytrunc = 0;
ulong fldmiss = 0;
int verbosity = 1;
int strict = 0;

struct clopt options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_STRING('k', NULL, "KEYTYPE",
		       "Set the key type to sort on"),
	CLOPT_I_NOARG('q', NULL, "decrease verbosity"),
	CLOPT_I_NOARG('r', NULL, "reverse the direction of the sort"),
	CLOPT_I_NOARG('s', NULL, "strict node"),
	CLOPT_I_NOARG('v', NULL, "increase verbosity"),
};
struct clopt_parser oparse =
CLOPTPARSER_INIT(options, array_length(options));

#define DEFAULT_KEYTYPE	"xpkt.timestamp"


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n"
			"Options:\n%s\n", progname, str);
	fprintf(stderr, "\nKEYTYPE can be one of:\n");
	fprintf(stderr, "\t'xpkt.timestamp', 'xpkt.flowid', 'xpkt.class', \n"
			"\t'xpkt.seq', 'xpkt.[+]appinfo'\n");
	fprintf(stderr, "The default keytype is '%s'.\n", DEFAULT_KEYTYPE);
	fprintf(stderr, "The 'xpkt.+appinfo' includes the subtype, "
			"'xpkt.appinfo' does not.\n");
	fprintf(stderr, "\nIn strict mode, if a key can not be built\n");
	fprintf(stderr, "exactly as specified, psort exits with an error.\n");
	exit(1);
}


static void add_kfxpkt(const char *name, int tagtype, int aisub)
{
	struct kfxpkt *kxf;
	kxf = &keyfields[numkf++].xpkt;
	kxf->type = KF_XPKT;
	kxf->name = name;
	kxf->tagtype = tagtype;
	kxf->aisub = aisub;
}


static void add_kfnspf(const char *name)
{
	struct kfnspf *kpf;
	struct ns_elem *e;
	kpf = &keyfields[numkf++].nspf;
	kpf->name = name;
	kpf->type = KF_NSPF;
	kpf->idx = 0;
	e = ns_lookup(NULL, name);
	if (e == NULL || e->type != NST_PKTFLD)
		err("Invalid packet field type: %s\n", name);
	kpf->pf = (struct ns_pktfld *)e;
}


static void add_key_type(const char *kts)
{
	if (numkf == array_length(keyfields))
		err("Too many key fields\n");

	if (strcmp(kts, "xpkt.timestamp") == 0) {
		add_kfxpkt(kts, XPKT_TAG_TIMESTAMP, 0);
	} else if (strcmp(kts, "xpkt.flowid") == 0) {
		add_kfxpkt(kts, XPKT_TAG_FLOW, 0);
	} else if (strcmp(kts, "xpkt.class") == 0) {
		add_kfxpkt(kts, XPKT_TAG_CLASS, 0);
	} else if (strcmp(kts, "xpkt.seq") == 0) {
		add_kfxpkt(kts, XPKT_TAG_SEQ, 0);
	} else if (strcmp(kts, "xpkt.appinfo") == 0) {
		add_kfxpkt(kts, XPKT_TAG_APPINFO, 0);
	} else if (strcmp(kts, "xpkt.*appinfo") == 0) {
		add_kfxpkt(kts, XPKT_TAG_APPINFO, 1);
	} else {
		add_kfnspf(kts);
	}
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
		case 'k':
			add_key_type(opt->val.str_val);
			break;
		case 'q':
			--verbosity;
			break;
		case 'r':
			reverse = 1;
			break;
		case 's':
			strict = 1;
			break;
		case 'v':
			++verbosity;
		}
	}
	if (rv < 0)
		usage(oparse.errbuf);

	if (numkf == 0)
		add_key_type(DEFAULT_KEYTYPE);

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


void check_strict(const char *s, const char *fn, ulong pn)
{
	if (strict) {
		err("Packet %lu: %s in field '%s' in strict mode: exiting\n",
		    pn, s, fn);
	} else if (verbosity > 1) {
		fprintf(stderr, "Packet %lu: %s in field '%s'.\n", pn, s, fn);
	}
}


void read_packets(struct list *pl)
{
	int rv;
	struct pktbuf *p;
	ulong pn = 0;

	l_init(pl);
	while ((rv = pkb_file_read_a(&p, infile, NULL, NULL)) > 0) {
		++pn;
		if (pkb_parse(p) < 0)
			err("Error parsing packet %lu\n", pn);
		l_enq(pl, &p->entry);
	}
	if (rv < 0)
		errsys("pkb_file_read_a(): ");
}


int add_xpkt_key(struct kfxpkt *kxf, struct pktbuf *p, int koff, ulong pn)
{
	int maxlen;
	int nb;
	byte_t tbuf[8];
	byte_t *bp = tbuf;
	struct xpkt_tag_hdr *xh;
	struct xpkt_tag_ts *xts;
	struct xpkt_tag_flowid *xf;
	struct xpkt_tag_class *xc;
	struct xpkt_tag_seq *xseq;
	struct xpkt_tag_appinfo *xai;

	maxlen = sizeof(p->cb) - koff;
	xh = pkb_find_tag(p, kxf->tagtype, 0);
	if (xh == NULL) {
		++fldmiss;
		check_strict("Lookup miss", kxf->name, pn);
		return koff;
	}

	switch (kxf->tagtype) {
	case XPKT_TAG_TIMESTAMP:
		xts = (struct xpkt_tag_ts *)xh;
		nb = pack(tbuf, sizeof(tbuf), "ww", xts->sec, xts->nsec);
		break;
	case XPKT_TAG_FLOW:
		xf = (struct xpkt_tag_flowid *)xh;
		nb = pack(tbuf, sizeof(tbuf), "ww", (ulong)(xf->flowid >> 32),
		          (ulong)(xf->flowid & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_CLASS:
		xc = (struct xpkt_tag_class *)xh;
		nb = pack(tbuf, sizeof(tbuf), "ww", (ulong)(xc->tag >> 32),
		          (ulong)(xc->tag & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_SEQ:
		xseq = (struct xpkt_tag_seq *)xh;
		nb = pack(tbuf, sizeof(tbuf), "ww", (ulong)(xseq->seq >> 32),
		          (ulong)(xseq->seq & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_APPINFO:
		nb = 0;
		xai = (struct xpkt_tag_appinfo *)xh;
		if (kxf->aisub) {
			if (maxlen >= 2) {
				pack(p->cb + koff, maxlen, "h", xai->subtype);
				koff += 2;
				maxlen -= 2;
			} else {
				if (maxlen == 1) {
					*(p->cb + koff) = 
						(xai->subtype >> 8) & 0xFF;
					maxlen = 0;
					++koff;
				}
				++keytrunc;
				check_strict("Truncated key", kxf->name, pn);
				return koff;
			}
		}
		bp = xai->data;
		nb = xai->nwords * 4;
		break;
	default:
		abort_unless(0);
	}

	if (nb > maxlen) {
		nb = maxlen;
		++keytrunc;
		check_strict("Truncated key", kxf->name, pn);
	}

	memmove(p->cb + koff, bp, nb);

	return koff + nb;
}


int add_nspf_key(struct kfnspf *kpf, struct pktbuf *p, int koff, ulong pn)
{
	struct ns_pktfld *pf = kpf->pf;
	int maxlen = sizeof(p->cb) - koff;
	void *pfp;
	byte_t *kp;
	ulong len;
	ulong val;

	if (maxlen <= 0) {
		++keytrunc;
		check_strict("Truncated key", kpf->name, pn);
		return koff;
	}

	kp = p->cb + koff;

	if (NSF_IS_INBITS(pf->flags)) {
		if (fld_get_vi(p->buf, &p->prp, pf, kpf->idx, &val) < 0) {
			++fldmiss;
			check_strict("Lookup miss", kpf->name, pn);
			return koff;
		}
		len = (pf->len + 7) / 8;
		switch(len) {
		case 4: *kp++ = (val >> 24) & 0xFF;
			if (--maxlen <= 0) { 
				++keytrunc; 
				check_strict("Truncated key", kpf->name, pn);
				break; 
			}
		case 3: *kp++ = (val >> 16) & 0xFF;
			if (--maxlen <= 0) {
				++keytrunc;
				check_strict("Truncated key", kpf->name, pn);
				break; 
			}
		case 2: *kp++ = (val >> 8) & 0xFF;
			if (--maxlen <= 0) {
				++keytrunc;
				check_strict("Truncated key", kpf->name, pn);
				break;
			}
		case 1: *kp = val & 0xFF;
			break;
		default:
			abort_unless(0);
		}
	} else {
		pfp = fld_get_pi(p->buf, &p->prp, pf, kpf->idx, &len);
		if (pfp == NULL) {
			++fldmiss;
			check_strict("Lookup miss", kpf->name, pn);
			return koff;
		}
		if (len > maxlen) {
			len = maxlen;
			++keytrunc;
			check_strict("Truncated key", kpf->name, pn);
		}
		memmove(kp, pfp, len);
	}

	return koff + len;
}


void set_key(struct pktbuf *p, ulong pn)
{
	int koff = 0;
	int i;
	memset(p->cb, 0x0, sizeof(p->cb));
	for (i = 0; i < numkf; ++i) {
		if (keyfields[i].type == KF_XPKT) {
			koff = add_xpkt_key(&keyfields[i].xpkt, p, koff, pn);
		} else {
			abort_unless(keyfields[i].type == KF_NSPF);
			koff = add_nspf_key(&keyfields[i].nspf, p, koff, pn);
		}
	}
}


void load_keys(struct list *pl)
{
	struct list *l;
	ulong pn = 0;
	l_for_each(l, pl)
		set_key(container(l, struct pktbuf, entry), ++pn);

	if (keytrunc > 0 && verbosity > 0)
		fprintf(stderr, "Key truncacted %lu times\n", keytrunc);
	if (fldmiss > 0 && verbosity > 0)
		fprintf(stderr, "Field lookup missed %lu times\n", fldmiss);
}


static int pkb_cmp(const void *le1, const void *le2)
{
	register const struct pktbuf *p1, *p2;
	int rv;
	p1 = container(le1, struct pktbuf, entry);
	p2 = container(le2, struct pktbuf, entry);
	rv = memcmp(p1->cb, p2->cb, sizeof(p1->cb));
	if (reverse)
		rv = rv < 0 ? 1 : ((rv > 0) ? -1 : 0);
	return rv;
}


void sort_packets(struct list *pl)
{
	l_sort(pl, pkb_cmp);
}


void write_packets(struct list *pl)
{
	struct list *l;
	struct pktbuf *p;

	while ((l = l_deq(pl)) != NULL) {
		p = container(l, struct pktbuf, entry);
		pkb_pack(p);
		if (pkb_file_write(p, outfile) < 0)
			errsys("pkb_file_write(): ");
		pkb_free(p);
	}
}


int main(int argc, char *argv[])
{
	struct list pl;

	pkb_init_pools(128);
	register_std_proto();
	parse_args(argc, argv);
	read_packets(&pl);
	load_keys(&pl);
	sort_packets(&pl);
	write_packets(&pl);

	return 0;
}
