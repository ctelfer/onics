/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * pdiff.c -- Compute the difference between two packet streams.
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

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <cat/err.h>
#include <cat/emalloc.h>
#include <cat/crypto.h>
#include <cat/stdclio.h>
#include <cat/emit_format.h>
#include <cat/str.h>
#include <cat/sort.h>
#include <cat/optparse.h>

#include "ns.h"
#include "pktbuf.h"
#include "stdproto.h"
#include "fld.h"
#include "util.h"


/* 
 * This program computes the edit distance between two packet streams by
 * looking at the data stream at increasing levels of granularity.  It 
 * computes damerau-levenshtein distance between the packets themselves.
 * This means it uses dynamic programming to determine the minimum cost
 * of insertions, deletions, modifications and swaps to transform the
 * first packet stream into the second.  The cost of inserting or deleting
 * a packet is fixed cost heuristically chosen.  The cost for modifying
 * a packet to produce another packet takes the packet scrutiny to 
 * the next layer of examination.
 *
 * Determining packet modification cost occurs by computing edit distance
 * first among the parsed headers in the packet.  The cost of inserting
 * a header is equal to the total cost of inserting a packet times the
 * fraction of the bits in the final packet that were inserted.  For 
 * example, if the target packet was 256 bits long and the cost of inserting
 * a packet were 8, then the cost of inserting a 64-bit header would be 
 * equal to 8 * 64 / 256 or 2.0.  Similarly, the cost of deleting a header is
 * equal to the cost of deleting an entire packet multiplied by the fraction
 * of bits from the original packet that were removed.  Computing the cost
 * of modifying a header takes the computation to a 3rd level of edit distance
 * calculation.
 *
 * The program only considers it possible to modify one protocol unit into 
 * another if they are have the exact same PRID.  The modification cost
 * of, say an IPv6 header into an IPv4 header would be infinity.  It will
 * be cheaper to delete the IPv6 header and insert the IPv4 header.  When
 * computing the edit distance between two protocol parses, the program
 * computes edit distance again this time against fields within the
 * protocol.  These include both named fields and unparsed data gaps.
 * This allows the program to detect not only that, say, the difference
 * between two packets was decrement of the TTL field, but also that,
 * say, a timestamp option was inserted into the packet.  (or removed).
 * The cost of inserting or removing a field is, again, the packet
 * insertion or removal cost weighted by the fraction of bits being
 * removed multiplied by a small constant > 1 to ensure that the program
 * considers modification of the same field always preferable to the sequence
 * of deletion and insertion.  The cost of field modification is equal to
 * the sum of the packet insertion and deletion cost with that sum multiplied
 * by the fraction of bits being modified.
 *
 *
 * TODO:
 *  + Enable ability to report changes as a PML edit script from the 
 *    original packet stream.
 *  + Perhaps operate on a _window_ of the packerts at a time to
 *    support larger streams more scalaby.  (memory usage is proportional
 *    to N*M where N is the size of stream 1 and M is the size of stream 2).
 */


/* potential edit operations: done indicates that the edit is complete */
enum {
	DONE,
	PASS,
	DROP,
	INSERT,
	MODIFY,
};


/* an entry in a list of data about the prparses in a packet */
struct prpent {
	struct prparse *	prp;
	struct npf_list		npfl;
	int			idx;
	ulong			nbits;
};


/* an entry with the comparison data for a given packet */
struct pktent {
	struct pktbuf *		pkt;
	struct prpent * 	prparr;
	int			nprp;
	ulong			pasiz;
	byte_t			hash[32];
};


/* an array of packets */
struct pktarr {
	struct pktent *		pkts;
	ulong			npkts;
	ulong			pasz;
};


/* An entry in the edit-distance calculation matrix */
struct chgpath {
	short			actb;
	short			actf;
	ulong			shift;
	ulong			opkt;
	ulong			r;
	ulong			c;
	double			cost;
	struct chgpath *	next;	/* filled in after backtrace */
};


/*
 * An NxM array of chgpath used to calculate edit distance.
 * The program uses this structure for computations at all levels
 * of abstraction.
 */
struct cpmatrix {
	struct chgpath **	elems;
	ulong			nrows;
	ulong			ncols;
};

#define cpm_elem(cpm, r, c) (&(cpm)->elems[r][c])



/* field difference comparitor */
struct fdiff {
	struct npf_list	*	before;
	struct npf_list	*	after;
	ulong			nb;
	ulong			na;
	struct cpmatrix		cpm;
	ulong			cpm_maxr;
	ulong			cpm_maxc;
	double			drop_bit_cost;
	double			ins_bit_cost;
};


/* header difference comparator */
struct hdiff {
	struct pktent *		bpke;
	struct pktent *		apke;
	struct cpmatrix		cpm;
	ulong			cpm_maxr;
	ulong			cpm_maxc;
};


/* packet difference comparitor */
struct pdiff {
	struct pktarr 		before;
	struct pktarr 		after;
	ulong			nb;
	ulong			na;
	struct cpmatrix		cpm;
	double **		mcosts;
};


/* Globals */

int verbosity = 0;
const char *progname;

struct clopt g_options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_NOARG('M', NULL, "disallow packet modifications"),
	CLOPT_I_NOARG('v', NULL, "increase verbosity"),
};
struct clopt_parser g_oparse = CLOPTPARSER_INIT_ARR(g_options);

const char *filename1;
const char *filename2;

/*
 * Basic cost constants.  Dropping is less than half as costly as insertion.
 * Modification cost equals drop plus insertion cost.  The algorithm should
 * only choose an operation with a cost of Infinity if operatins needed
 * to edit successfully had a cost of Infinity.  But this should almost never
 * be the case for our selection.  At the very least dropping one packet
 * and inserting another will be cheaper.
 */
double Pkt_drop_cost = 2;
double Pkt_ins_cost = 5;
double Pkt_mod_cost = 7;
double Infinity = 1e20;

/* we really just need one hdiff and fdiff comparitor each */
/* We can reuse them easily from one packet/header to the next. */
struct hdiff Hdiff;
struct fdiff Fdiff;

/* used to help enumerate the fields in a packet for nice printing */
static struct npfield **	Farr = NULL;
static uint 			Fasiz = 0;

int disallow_mods = 0;

double pkt_cmp(struct pktent *pke1, ulong pke1n, struct pktent *pke2,
	       ulong pke2n);

void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] FILE1 FILE2\n%s\n", progname, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	
	progname = argv[0];
	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch(opt->ch) {
		case 'h':
			usage(NULL);
			break;
		case 'M':
			disallow_mods = 1;
			break;
		case 'v':
			++verbosity;
			break;
		}
	}

	if (rv < 0)
		usage(g_oparse.errbuf);
	if (rv > argc - 2)
		usage("Incorrect # of arguments\n");
	filename1 = argv[rv];
	filename2 = argv[rv+1];
}


static void hash_packet(struct pktent *pke)
{
	struct pktbuf *p = pke->pkt;
	sha256(pkb_data(p), pkb_get_len(p), pke->hash);
}


/* filter the field out if it isn't a packet field */
static int nsfilter(struct ns_elem *elem)
{
	return elem->type != NST_PKTFLD;
}


ulong npfl_nbits(struct npf_list *npfl)
{
	ulong nbits = 0;
	struct npfield *npf;
	for (npf = npfl_first(npfl); !npf_is_end(npf); npf = npf_next(npf))
		nbits += npf->len;
	return nbits;
}


void pktent_init(struct pktent *pke, ulong pn, const char *sname)
{
	struct prparse *prp;
	struct prpent *ppe;
	int i;

	hash_packet(pke);
	pke->nprp = 0;
	pke->pasiz = 8;
	pke->prparr = emalloc(sizeof(struct prpent) * pke->pasiz);

	ppe = pke->prparr;
	prp_for_each(prp, &pke->pkt->prp) {
		if (pke->nprp == pke->pasiz) {
			pke->pasiz *= 2;
			pke->prparr = erealloc(pke->prparr,
					       sizeof(struct prpent) * 
							pke->pasiz);
			ppe = &pke->prparr[pke->nprp];
		}
		pke->nprp += 1;
		ppe->prp = prp;
		for (i = pke->nprp-2; i >= 0; --i)
			if (pke->prparr[i].prp->prid == prp->prid)
				++ppe->idx;
		npfl_init(&ppe->npfl, &pke->pkt->prp, pke->pkt->buf);
		if (npfl_load(&ppe->npfl, prp, 1, nsfilter) < 0)
			errsys("pktent_init() calling npfl_load()");
		ppe->nbits = npfl_nbits(&ppe->npfl);
		ppe = &pke->prparr[pke->nprp];
	}
}


static void pa_readfile(struct pktarr *pa, FILE *fp, const char *fn)
{
	int rv;
	struct pktent *pke;

	pa->pasz = 16;
	pa->pkts = emalloc(sizeof(struct pktent) * pa->pasz);
	pa->npkts = 0;

	pke = &pa->pkts[pa->npkts];
	rv = pkb_file_read(&pke->pkt, fp);
	while (rv > 0) {
		if (pkb_parse(pke->pkt) < 0)
			err("unable to parse packet %lu\n", pa->npkts+1);
		pktent_init(pke, pa->npkts+1, fn);
		++pa->npkts;
		if (pa->npkts == pa->pasz) {
			if (pa->pasz * 2 < pa->pasz)
				err("Size overflow\n");
			pa->pasz *= 2;
			pa->pkts = erealloc(pa->pkts, 
					    pa->pasz * sizeof(struct pktent));
		}
		pke = &pa->pkts[pa->npkts];
		rv = pkb_file_read(&pke->pkt, fp);
	}

	if (rv < 0)
		errsys("Error reading packet for file %s", fn);
}


static void pa_clear(struct pktarr *pa)
{
	struct pktent *pke;
	ulong np;
	int i;

	if (pa == NULL)
		return;

	pke = pa->pkts;
	for (np = 0; np < pa->npkts; ++np) {
		for (i = 0; i < pke->nprp; ++i) {
			npfl_cache(&pke->prparr[i].npfl);
			pke->prparr[i].prp = NULL;
			pke->prparr[i].idx = 0;
			pke->prparr[i].nbits = 0;
		}
		free(pke->prparr);
		pkb_free(pke->pkt);
		pke++;
	}

	memset(pa->pkts, 0, sizeof(struct pktent) * pa->npkts);
	pa->npkts = 0;
	free(pa->pkts);
	pa->pkts = NULL;
}


static void cpm_ealloc(struct cpmatrix *cpm, ulong nr, ulong nc)
{
	struct chgpath *cpe;
	struct chgpath **rp;
	ulong i, j;

	abort_unless(nr > 0 || nc > 0 || 
		     ULONG_MAX / sizeof(struct chgpath) / nc <= nr);

	cpm->nrows = nr;
	cpm->ncols = nc;
	cpm->elems = ecalloc(sizeof(struct chgpath *), nr);
	cpe = ecalloc(sizeof(struct chgpath), nr * nc);

	rp = cpm->elems;
	for (i = 0; i < nr; ++i) {
		for (j = 0; j < nc; ++j) {
			cpe[j].r = i;
			cpe[j].c = j;
		}
		*rp++ = cpe;
		cpe += nc;
	}
}


void cpm_clear(struct cpmatrix *cpm)
{
	if (cpm->elems == NULL)
		return;
	free(cpm->elems[0]);
	memset(cpm->elems, 0, sizeof(struct chgpth *) * cpm->nrows);
	free(cpm->elems);
	cpm->elems = NULL;
}


void cpm_backtrace(struct cpmatrix *cpm)
{
	ulong r = cpm->nrows-1;
	ulong c = cpm->ncols-1;
	struct chgpath *elem, *prev;

	abort_unless(r == cpm->nrows - 1);
	abort_unless(c == cpm->ncols - 1);

	elem = cpm_elem(cpm, r, c);
	elem->actf = DONE;
	while (elem->actb != DONE) {
		abort_unless(r < cpm->nrows && c < cpm->ncols);

		switch(elem->actb) {
		case PASS: 	r -= 1; c -= 1; break;
		case DROP: 	r -= 1; break;
		case INSERT: 	c -= 1; break;
		case MODIFY:	r -= 1; c -= 1; break;
		default:	abort_unless(0);
		}

		prev = cpm_elem(cpm, r, c);
		prev->next = elem;
		prev->actf = elem->actb;
		elem = prev;
	}
}


static void getmincost(struct chgpath *p, double icost, double dcost,
		       double mcost, int maction)
{
	/* bias towards modify */
	if (icost < dcost) {
		if (icost < mcost) {
			p->actb = INSERT;
			p->cost = icost;
		} else {
			p->actb = maction;
			p->cost = mcost;
		}
	} else {
		if (dcost < mcost) {
			p->actb = DROP;
			p->cost = dcost;
		} else {
			p->actb = maction;
			p->cost = mcost;
		}
	}
}


void pdiff_load(struct pdiff *pd, FILE *before, const char *bname, 
		FILE *after, const char *aname)
{
	double *dp;
	double cost;
	ulong i, j;

	pa_readfile(&pd->before, before, bname);
	pa_readfile(&pd->after, after, aname);
	pd->nb = pd->before.npkts;
	pd->na = pd->after.npkts;
	cpm_ealloc(&pd->cpm, pd->nb+1, pd->na+1);

	/* precompute pair-wise modification costs between each packet */
	pd->mcosts = calloc(sizeof(double *), pd->nb);
	dp = calloc(sizeof(double), pd->nb * pd->na);
	for (i = 0; i < pd->nb; ++i) {
		pd->mcosts[i] = dp;
		dp += pd->na;
		for (j = 0; j < pd->na; ++j) {
			cost = pkt_cmp(&pd->before.pkts[i], i+1,
				       &pd->after.pkts[j], j+1);
			if (cost != 0.0 && disallow_mods)
				cost = Infinity;
			pd->mcosts[i][j] = cost;
		}
	}
}


void pdiff_clear(struct pdiff *pd)
{
	if (pd == NULL)
		return;
	pa_clear(&pd->before);
	pa_clear(&pd->after);
	cpm_clear(&pd->cpm);
	pd->na = 0;
	pd->nb = 0;
	free(pd->mcosts[0]);
	free(pd->mcosts);
	pd->mcosts = NULL;
}


void fdiff_init(struct fdiff *fd)
{
	memset(fd, 0, sizeof(*fd));
	fd->cpm_maxr = 0;	/* explicit */
	fd->cpm_maxc = 0;	/* explicit */
}


void fdiff_load(struct fdiff *fd, struct npf_list *fl1, struct npf_list *fl2)
{
	fd->before = fl1;
	fd->after = fl2;
	fd->nb = npfl_get_len(fd->before);
	fd->na = npfl_get_len(fd->after);

	if (fd->nb+1 <= fd->cpm_maxr && fd->na+1 <= fd->cpm_maxc) {
		fd->cpm.nrows = fd->nb + 1;
		fd->cpm.ncols = fd->na + 1;
	} else {
		if (fd->cpm_maxr > 0) {
			cpm_clear(&fd->cpm);
			fd->cpm.nrows = 0;
			fd->cpm.ncols = 0;
		}
		cpm_ealloc(&fd->cpm, fd->nb+1, fd->na+1);
		fd->cpm_maxr = fd->cpm.nrows;
		fd->cpm_maxc = fd->cpm.ncols;
	}
}


static double calc_fmod_cost(struct npfield *f1, double f1cost, 
			     struct npfield *f2, double f2cost)
{
	double cost;
	double bytecost;
	byte_t *p1;
	byte_t *p2;
	ulong i;
	ulong n;
	ulong l;

	if (!npf_is_gap(f1)) {
		return f1->len * f1cost + f2->len * f2cost;
	} else {
		abort_unless((f1->len & 7) == 0);
		abort_unless((f2->len & 7) == 0);

		cost = 0.0;
		bytecost = (f1cost + f2cost) * 8;
		l = ((f1->len < f2->len) ? f1->len : f2->len) / 8;
		p1 = f1->buf + f1->off / 8;
		p2 = f2->buf + f2->off / 8;
		i = 0;

		while (i < l) {
			while (i < l && *p1 == *p2) {
				++i; ++p1; ++p2;
			}
			n = 0;
			while (i < l && *p1 != *p2) {
				++i; ++p1; ++p2; ++n;
			}
			cost += n * bytecost;
		}

		if (i > f1->len / 8)
			cost += (f1->len - (i * 8)) * f1cost;
		else if (i < f2->len / 8)
			cost += (f2->len - (i * 8)) * f2cost;

		return cost;
	}
}
		  
		  
void fdiff_clear(struct fdiff *fd)
{
	fd->before = NULL;
	fd->after = NULL;
}
		  
		  
void fdiff_free(struct fdiff *fd)
{
	fd->before = NULL;
	fd->after = NULL;
	cpm_clear(&fd->cpm);
	fd->cpm.nrows = 0;
	fd->cpm.ncols = 0;
}
		  

double fdiff_cost(struct fdiff *fd)
{
	return cpm_elem(&fd->cpm, fd->nb, fd->na)->cost;
}


void fdiff_compare(struct fdiff *fd, double drop_bit_cost, double ins_bit_cost)
{
	ulong i, j;
	int maction;
	double mcost;
	double icost;
	double dcost;
	struct cpmatrix *cpm = &fd->cpm;
	struct chgpath *ipos, *dpos, *mpos;
	struct npf_list *rnpfl = fd->before;
	struct npf_list *cnpfl = fd->after;
	struct npfield *rnpf;
	struct npfield *cnpf;
	double adj_drop_bit_cost = drop_bit_cost * 1.05;
	double adj_ins_bit_cost = ins_bit_cost * 1.05;

	cpm_elem(cpm, 0, 0)->actb = DONE;
	cpm_elem(cpm, 0, 0)->cost = 0.0;
	rnpf = npfl_first(rnpfl);
	for (i = 1; i < cpm->nrows; ++i) {
		dpos = cpm_elem(cpm, i, 0);
		dpos->actb = DROP;
		dpos->cost = cpm_elem(cpm, i-1, 0)->cost + 
			     rnpf->len * adj_drop_bit_cost;
		rnpf = npf_next(rnpf);
	}

	cnpf = npfl_first(cnpfl);
	for (i = 1; i < cpm->ncols; ++i) {
		ipos = cpm_elem(cpm, 0, i);
		ipos->actb = INSERT;
		ipos->cost = cpm_elem(cpm, 0, i-1)->cost + 
			     cnpf->len * adj_ins_bit_cost;
		cnpf = npf_next(cnpf);
	}

	rnpf = npfl_first(rnpfl);
	for (i = 1; i < cpm->nrows; ++i) {
		cnpf = npfl_first(cnpfl);
		for (j = 1; j < cpm->ncols; ++j) {
			ipos = cpm_elem(cpm, i, j-1);
			dpos = cpm_elem(cpm, i-1, j);
			mpos = cpm_elem(cpm, i-1, j-1);

			if (npf_eq(rnpf, cnpf)) {
				mcost = mpos->cost;
				maction = PASS;
			} else if (npf_type_eq(rnpf, cnpf)) {
				mcost = mpos->cost + 
					calc_fmod_cost(rnpf, drop_bit_cost,
						       cnpf, ins_bit_cost);
				maction = MODIFY;
			} else {
				mcost = Infinity;
				maction = MODIFY;
			}

			dcost = dpos->cost + adj_drop_bit_cost * rnpf->len;
			icost = ipos->cost + adj_ins_bit_cost * cnpf->len;

			getmincost(cpm_elem(cpm, i, j), icost, dcost, mcost,
				   maction);
			cnpf = npf_next(cnpf);
		}
		rnpf = npf_next(rnpf);
	}
}


static void prp_get_name(struct prparse *prp, int idx, char *str, size_t smax)
{
	struct ns_namespace *ns;
	char istr[32];

	if (idx == 0)
		istr[0] = '\0';
	else
		str_fmt(istr, sizeof(istr), " -- %d", idx);

	ns = ns_lookup_by_prid(prp->prid);
	if (ns != NULL)
		str_fmt(str, smax, "%s%s", ns->fullname, istr);
	else
		str_fmt(str, smax, "PRID-%d%s", prp->prid, istr);

}


static void emit_field(struct emitter *e, struct npf_list *npfl,
		       struct npfield *npf, const char *pfx)
{
	char line[256];
	ulong base_off;
	ulong off;
	ulong len;
	ulong sboff;
	int rv;

	base_off = prp_poff(npfl->plist);

	if (!npf_is_gap(npf)) {
		rv = ns_tostr(npf->nse, npf->buf, npf->prp, line, sizeof(line),
			      pfx);
		if (rv >= 0)
			emit_string(e, line);
	} else {
		off = npf->off / 8;
		len = npf->len;
		if (npf->off % 8 != 0)
			len += 8 - (npf->off % 8);
		len = (len + 7) / 8;

		prp_get_name(npf->prp, 0, line, sizeof(line));
		sboff = off - base_off;
		emit_format(e, "%s%s Data -- [%lu:%lu]\n", pfx, line, sboff, len);
		emit_hex(e, pfx, sboff, npf->buf + off, len);
	}
}


static void emit_fmod_gap(struct emitter *e, struct npf_list *npfl1,
			  struct npfield *f1, struct npf_list *npfl2,
			  struct npfield *f2)
{
	char name[64];
	byte_t *p1 = f1->buf + f1->off / 8;
	byte_t *p2 = f2->buf + f2->off / 8;
	ulong l = ((f1->len < f2->len) ? f1->len : f2->len) / 8;
	ulong i = 0;
	ulong n;
	ulong sboff1 = f1->off / 8 - prp_poff(npfl1->plist);
	ulong sboff2 = f2->off / 8 - prp_poff(npfl2->plist);

	prp_get_name(f1->prp, 0, name, sizeof(name));

	while (i < l) {
		while (i < l && *p1 == *p2) {
			++i; ++p1; ++p2;
		}
		n = 0;
		while (i+n < l && p1[n] != p2[n])
			++n;
		if (n > 0) {
			emit_format(e, "%%-%s Data -- [%lu:%lu]\n", name, 
				    sboff1 + i, n);
			emit_hex(e, "%-", sboff1 + i, p1, n);
			emit_format(e, "%%+%s Data -- [%lu:%lu]\n", name, 
				    sboff2 + i, n);
			emit_hex(e, "%+", sboff2 + i, p2, n);
			p1 += n;
			p2 += n;
			i += n;
		}
	}
}


static void mod_fld_report(struct emitter *e, struct npf_list *npfl1,
			   struct npfield *npf1, struct npf_list *npfl2,
			   struct npfield *npf2)
{

	if (!npf_is_gap(npf1)) {
		emit_field(e, npfl1, npf1, "%- ");
		emit_field(e, npfl2, npf2, "%+ ");
	} else {
		emit_fmod_gap(e, npfl1, npf1, npfl2, npf2);
	}
}


static void mod_hdr_report(struct emitter *e, struct prpent *ppe1, ulong p1n,
			   struct prpent *ppe2, ulong p2n, 
			   double drop_bit_cost, double ins_bit_cost)
{
	struct cpmatrix *cpm;
	struct chgpath *elem;
	struct npfield *rnpf, *cnpf;
	char line[256];
	struct npf_list *bnpfl, *anpfl;

	bnpfl = &ppe1->npfl;
	anpfl = &ppe2->npfl;

	fdiff_load(&Fdiff, bnpfl, anpfl);
	fdiff_compare(&Fdiff, drop_bit_cost, ins_bit_cost);
	cpm = &Fdiff.cpm;
	cpm_backtrace(cpm);

	elem = cpm_elem(cpm, 0, 0);
	rnpf = npfl_first(bnpfl);
	cnpf = npfl_first(anpfl);

	while (elem->actf != DONE) {
		switch (elem->actf) {
		case PASS: 
			if (verbosity > 0) {
				ns_tostr(rnpf->nse, rnpf->buf, rnpf->prp, line,
					 sizeof(line), "   ");
				emit_string(e, line);
			}
			rnpf = npf_next(rnpf);
			cnpf = npf_next(cnpf);
			break;

		case DROP:
			ns_tostr(rnpf->nse, rnpf->buf, rnpf->prp, line, 
				 sizeof(line), "-- ");
			emit_string(e, line);
			rnpf = npf_next(rnpf);
			break;

		case INSERT:
			ns_tostr(cnpf->nse, cnpf->buf, cnpf->prp, line,
				 sizeof(line), "++ ");
			emit_string(e, line);
			cnpf = npf_next(cnpf);
			break;

		case MODIFY:
			mod_fld_report(e, bnpfl, rnpf, anpfl, cnpf);
			rnpf = npf_next(rnpf);
			cnpf = npf_next(cnpf);
			break;

		default: abort_unless(0);
		}

		elem = elem->next;
		abort_unless(elem != NULL);
	}

	fdiff_clear(&Fdiff);
}


void hdiff_init(struct hdiff *hd)
{
	memset(hd, 0, sizeof(*hd));
	hd->cpm_maxr = 0;	/* explicit */
	hd->cpm_maxc = 0;	/* explicit */
}


static double prp_cmp_long(struct prpent *ppe1, struct prpent *ppe2,
			   double drop_bit_cost, double ins_bit_cost)
{
	double cost;
	fdiff_load(&Fdiff, &ppe1->npfl, &ppe2->npfl);
	fdiff_compare(&Fdiff, drop_bit_cost, ins_bit_cost);
	cost = fdiff_cost(&Fdiff);
	fdiff_clear(&Fdiff);
	return cost;
}


static double prp_cmp(struct prpent *ppe1, struct prpent *ppe2,
		      double dcost, double icost)
{
	struct npfield *npf1, *npf2;
	double cost = 0.0;

	if (ppe1->prp->prid != ppe2->prp->prid)
		return Infinity;

	npf1 = npfl_first(&ppe1->npfl);
	npf2 = npfl_first(&ppe2->npfl);

	while (!npf_is_end(npf1) && !npf_is_end(npf2)) {
		if (!npf_eq(npf1, npf2)) {

			/* we have a field mismatch: need to do it the */
			/* long way: sad face */
			if (!npf_type_eq(npf1, npf2))
				return prp_cmp_long(ppe1, ppe2, dcost, icost);

			/* TODO:  better payload comparison/cost */
			/* right now it is just one large binary field */
			cost += dcost * npf1->len;
			cost += icost * npf2->len;
		}
		npf1 = npf_next(npf1);
		npf2 = npf_next(npf2);
	}

	/* if we hit this we extra bits at the end to remove: no prob */
	while (!npf_is_end(npf1)) {
		cost += dcost * npf1->len;
		npf1 = npf_next(npf1);
	}

	/* if we hit this we extra bits at the end to insert: no prob */
	while (!npf_is_end(npf2)) {
		cost += icost * npf2->len;
		npf2 = npf_next(npf2);
	}

	return cost;
}


void hdiff_load(struct hdiff *hd, struct pktent *pke1, struct pktent *pke2)
{
	hd->bpke = pke1;
	hd->apke = pke2;
	if (pke1->nprp+1 <= hd->cpm_maxr && pke2->nprp+1 <= hd->cpm_maxc) {
		hd->cpm.nrows = pke1->nprp + 1;
		hd->cpm.ncols = pke2->nprp + 1;
	} else {
		if (hd->cpm_maxr > 0) {
			cpm_clear(&hd->cpm);
			hd->cpm.nrows = 0;
			hd->cpm.ncols = 0;
		}
		cpm_ealloc(&hd->cpm, pke1->nprp + 1, pke2->nprp + 1);
		hd->cpm_maxr = hd->cpm.nrows;
		hd->cpm_maxc = hd->cpm.ncols;
	}
}


void hdiff_compare(struct hdiff *hd)
{
	ulong i, j;
	int maction;
	double mcost;
	double icost;
	double dcost;
	struct cpmatrix *cpm = &hd->cpm;
	struct chgpath *ipos, *dpos, *mpos;
	double drop_bit_cost, adj_drop_bit_cost;
	double ins_bit_cost, adj_ins_bit_cost;
	struct prpent *bppe, *appe;

	cpm_elem(cpm, 0, 0)->actb = DONE;
	cpm_elem(cpm, 0, 0)->cost = 0.0;

	/* 
	 * Each drop costs an amount proportional to the # of bits
	 * being dropped in from the packet.  Similarly, each insert
	 * costs an amount proportional to the # of bits inserted.
	 */
	drop_bit_cost = Pkt_mod_cost /
			(double)(pkb_get_len(hd->bpke->pkt) * 8);
	ins_bit_cost = Pkt_mod_cost /
		       (double)(pkb_get_len(hd->apke->pkt) * 8);

	/* weight drops for headers a bit higher than the base cost */
	adj_drop_bit_cost = drop_bit_cost * 1.05;
	adj_ins_bit_cost = ins_bit_cost * 1.05;

	for (i = 1; i < cpm->nrows; ++i) {
		dpos = cpm_elem(cpm, i, 0);
		dpos->actb = DROP;
		dpos->cost = cpm_elem(cpm, 0, i-1)->cost +
			     hd->bpke->prparr[i-1].nbits * adj_drop_bit_cost;
	}

	for (i = 1; i < cpm->ncols; ++i) {
		ipos = cpm_elem(cpm, 0, i);
		ipos->actb = INSERT;
		ipos->cost = cpm_elem(cpm, 0, i-1)->cost +
			     hd->apke->prparr[i-1].nbits * adj_ins_bit_cost;
	}

	bppe = hd->bpke->prparr;
	for (i = 1; i < cpm->nrows; ++i, ++bppe) {
		appe = hd->apke->prparr;
		for (j = 1; j < cpm->ncols; ++j, ++appe) {
			ipos = cpm_elem(cpm, i, j-1);
			dpos = cpm_elem(cpm, i-1, j);
			mpos = cpm_elem(cpm, i-1, j-1);

			mcost = prp_cmp(bppe, appe, drop_bit_cost,
					ins_bit_cost);
			maction = (mcost == 0.0) ? PASS : MODIFY;
			mcost += mpos->cost;

			dcost = dpos->cost + adj_drop_bit_cost * bppe->nbits;
			icost = ipos->cost + adj_ins_bit_cost * appe->nbits;

			getmincost(cpm_elem(cpm, i, j), icost, dcost, mcost,
				   maction);
		}
	}
}


double hdiff_cost(struct hdiff *hd)
{
	return cpm_elem(&hd->cpm, hd->cpm.nrows-1, hd->cpm.ncols-1)->cost;
}


void hdiff_clear(struct hdiff *hd)
{
	hd->bpke = NULL;
	hd->apke = NULL;
}


double pkt_cmp(struct pktent *pke1, ulong pke1n, struct pktent *pke2,
	       ulong pke2n)
{
	double cost;

	if (memcmp(pke1->hash, pke2->hash, sizeof(pke1->hash)) == 0)
		return 0.0;

	hdiff_load(&Hdiff, pke1, pke2);
	hdiff_compare(&Hdiff);
	cost = hdiff_cost(&Hdiff);
	hdiff_clear(&Hdiff);

	return cost;
}


/* TODO: handle swaps */
void pdiff_compare(struct pdiff *pd)
{
	ulong i, j;
	int maction;
	double mcost;
	double icost;
	double dcost;
	struct cpmatrix *cpm = &pd->cpm;
	struct chgpath *ipos, *dpos, *mpos;

	cpm_elem(cpm, 0, 0)->actb = DONE;
	cpm_elem(cpm, 0, 0)->cost = 0;

	for (i = 1; i < cpm->nrows; ++i) {
		dpos = cpm_elem(cpm, i, 0);
		dpos->actb = DROP;
		dpos->cost = i * Pkt_drop_cost;
	}

	for (i = 1; i < cpm->ncols; ++i) {
		ipos = cpm_elem(cpm, 0, i);
		ipos->actb = INSERT;
		ipos->cost = i * Pkt_ins_cost;
	}


	for (i = 1; i < cpm->nrows; ++i) {
		for (j = 1; j < cpm->ncols; ++j) {
			ipos = cpm_elem(cpm, i, j-1);
			dpos = cpm_elem(cpm, i-1, j);
			mpos = cpm_elem(cpm, i-1, j-1);

			mcost = pd->mcosts[i-1][j-1];
			maction = (mcost == 0.0) ? PASS : MODIFY;
			mcost += mpos->cost;
			icost = ipos->cost + Pkt_ins_cost;
			dcost = dpos->cost + Pkt_drop_cost;

			getmincost(cpm_elem(cpm, i, j), icost, dcost, mcost,
				   maction);
		}
	}

	cpm_backtrace(&pd->cpm);
}


static void print_hdr_desc(struct emitter *e, struct prpent *ppe, 
			   const char *op, const char *pfx)
{
	char name[256];
	struct prparse *prp;
	ulong psoff;

	prp = ppe->prp;
	psoff = prp_poff(ppe->npfl.plist);

	prp_get_name(prp, ppe->idx, name, sizeof(name));
	emit_format(e, "%s*****\n", pfx);
	emit_format(e, "%s* %s%s -- [%lu:%lu]\n", 
		    pfx, op, name, prp_soff(prp) - psoff,
		    prp_totlen(prp));
	emit_format(e, "%s*****\n", pfx);
}


static void print_hdr_op(struct emitter *e, struct prpent *ppe, int action)
{
	char *op;
	char *pfx;
	struct npfield *npf;

	switch (action) {
	case PASS:
		if (verbosity < 1)
			return;
		op = "";
		pfx = "   ";
		break;
	case DROP:
		op = "DROP header ";
		pfx = "H- ";
		break;
	case INSERT:
		op = "INSERT header ";
		pfx = "H+ ";
		break;
	}

	print_hdr_desc(e, ppe, op, pfx);

	for (npf = npfl_first(&ppe->npfl) ; !npf_is_end(npf) ;
	     npf = npf_next(npf)) {
		emit_field(e, &ppe->npfl, npf, pfx);
	}
}


static void mod_pkt_report(struct pktent *pke1, ulong p1n, struct pktent *pke2, 
			   ulong p2n, struct emitter *e)
{
	struct cpmatrix *cpm;
	struct chgpath *elem;
	struct prpent *rppe, *cppe;
	double drop_bit_cost;
	double ins_bit_cost;

	hdiff_load(&Hdiff, pke1, pke2);
	hdiff_compare(&Hdiff);
	cpm = &Hdiff.cpm;
	cpm_backtrace(cpm);

	drop_bit_cost = Pkt_mod_cost /
			(double)(pkb_get_len(pke1->pkt) * 8);
	ins_bit_cost = Pkt_mod_cost /
		       (double)(pkb_get_len(pke2->pkt) * 8);


	elem = cpm_elem(cpm, 0, 0);
	while (elem->actf != DONE)
	{
		rppe = &pke1->prparr[elem->r];
		cppe = &pke2->prparr[elem->c];

		switch (elem->actf) {
		case PASS:
		case DROP:
			print_hdr_op(e, rppe, elem->actf);
			break;
		case INSERT:
			print_hdr_op(e, cppe, elem->actf);
			break;
		case MODIFY:
			if (verbosity > 0)
				print_hdr_desc(e, rppe, "", "   ");
			mod_hdr_report(e, rppe, elem->r+1, cppe, elem->c+1,
				       drop_bit_cost, ins_bit_cost);
			break;
		default:
			abort_unless(0);
		}

		elem = elem->next;
		abort_unless(elem != NULL);
	}

	hdiff_clear(&Hdiff);
}


static int fld_off_cmp(const void *f1p, const void *f2p)
{
	struct npfield *f1, *f2;
	f1 = *(struct npfield **)f1p;
	f2 = *(struct npfield **)f2p;
	return (f1->off < f2->off) ? -1 : ((f1->off == f2->off) ? 0 : 1);
}


static struct prpent *find_prpe(struct pktent *pke, struct prparse *prp)
{
	int i;
	struct prpent *ppe;
	for (i = 0, ppe = pke->prparr; i < pke->nprp; ++i, ++ppe)
		if (ppe->prp == prp)
			return ppe;
	abort_unless(0);
	return NULL;
}


static void pke_print(struct emitter *e, struct pktent *pke, char *pfx)
{
	int i;
	int j;
	int n = 0;
	struct prpent *ppe;
	struct npfield *npf;
	struct prparse *prp, *lastprp;
	ulong soff;
	ulong psoff;
	char name[64];

	/* count the # of fields */
	for (i = 0, ppe = pke->prparr; i < pke->nprp; ++i, ++ppe)
		n += npfl_get_len(&ppe->npfl);

	/* resize the field array if necessary */
	if (n > Fasiz) {
		Farr = erealloc(Farr, n * sizeof(struct npfield *));
		Fasiz = n;
	}

	/* copy the pointers to the field pointer array */
	for (i = 0, j = 0, ppe = pke->prparr; i < pke->nprp; ++i, ++ppe)
		for (npf = npfl_first(&ppe->npfl) ; !npf_is_end(npf) ;
		     npf = npf_next(npf))
			Farr[j++] = npf;

	/* 
	 * sort the array by offset: list should be nearly 
	 * sorted so insertion sort should be very fast.
	 */
	isort_array(Farr, n, sizeof(Farr[0]), fld_off_cmp);

	/* print the fields */
	lastprp = NULL;
	psoff = pkb_get_off(pke->pkt);
	for (i = 0; i < n; ++i) {
		npf = Farr[i];

		/* check if field is in a new parse */
		if (npf->prp != lastprp) {
			prp = npf->prp;
			ppe = find_prpe(pke, prp);
			soff = prp_soff(prp) - psoff;
			prp_get_name(prp, ppe->idx, name, sizeof(name));
			emit_format(e, "%s*****\n", pfx);
			emit_format(e, "%s* %s: [%lu:%lu]\n", pfx, name, soff, 
				    prp_totlen(prp));
			emit_format(e, "%s*****\n", pfx);
			lastprp = prp;
		}

		emit_field(e, &ppe->npfl, npf, pfx);
	}
}


static int insdel_is_xpose(struct pdiff *pd, struct chgpath *e1,
			   struct chgpath *e2)
{
	if (e1->actf == DROP) {
		return e2->actf == INSERT && 
		       e2->shift == 0 &&
		       pd->mcosts[e1->r][e2->c] == 0.0;
	} else {
		abort_unless(e1->actf == INSERT);
		return e2->actf == DROP && 
		       e2->shift == 0 &&
		       pd->mcosts[e2->r][e1->c] == 0.0;
	}
}


int ck_report_reorder(struct pdiff *pd, struct chgpath *elem, struct emitter *e)
{
	struct chgpath *xpose = elem;
	struct pktent *pke;
	ulong npkts = 0;

	xpose = elem->next;
	while (xpose->actf != DONE) {
		if (insdel_is_xpose(pd, elem, xpose))
			break;
		if (xpose->actf != DROP)
			++npkts;
		xpose = xpose->next;
		abort_unless(xpose != NULL);
	}
	if (xpose->actf == DONE)
		return 0;

	xpose->shift = npkts;
	xpose->opkt = elem->r+1;

	if (elem->actf == DROP) {
		emit_string(e, "#####\n");
		emit_format(e, "# Packet %lu moved forward %lu packet%s\n", 
			    elem->r+1, npkts, (npkts > 1) ? "s" : "");
		emit_string(e, "#####\n");
		emit_string(e, "\n");
	} else {
		abort_unless(elem->actf == INSERT);
		emit_string(e, "#####\n");
		emit_format(e, "# Packet %lu moved backwards %lu packet%s\n",
			    xpose->r+1, npkts, (npkts > 1) ? "s" : "");
		emit_string(e, "#####\n");
		pke = &pd->after.pkts[elem->c];
		pke_print(e, pke, "<< ");
		emit_string(e, "\n");
	}
	
	return 1;
}


void pdiff_report(struct pdiff *pd, struct emitter *e)
{
	struct cpmatrix *cpm = &pd->cpm;
	struct chgpath *elem;
	struct pktent *pke;

	elem = cpm_elem(cpm, 0, 0);
	while (elem->actf != DONE) {
		switch (elem->actf) {
		case PASS: 
			if (verbosity > 0) {
				emit_string(e, "#####\n");
				emit_format(e, "# Pass packet %lu\n",
					    elem->r+1);
				emit_string(e, "#####\n");
				if (verbosity > 1) {
					pke = &pd->before.pkts[elem->r];
					pke_print(e, pke, "   ");
				}
				emit_string(e, "\n");
			}
			break;

		case DROP:
			pke = &pd->before.pkts[elem->r];
			if (elem->shift > 0) {
				emit_string(e, "#####\n");
				emit_format(e, "# Packet %lu moved backwards "
					       "%lu packet%s\n",
					    elem->r+1, 
					    elem->shift, 
					    elem->shift > 1 ? "s" : "");
				emit_string(e, "#####\n");
			} else if (!ck_report_reorder(pd, elem, e)) {
				emit_string(e, "#####\n");
				emit_format(e, "# DROP packet %lu\n", 
					    elem->r+1);
				emit_string(e, "#####\n");
				pke_print(e, pke, "-- ");
				emit_string(e, "\n");
			}
			break;

		case INSERT:
			pke = &pd->after.pkts[elem->c];
			if (elem->shift > 0) {
				emit_string(e, "#####\n");
				emit_format(e, "# Packet %lu moved forward "
					       "%lu packet%s\n",
					    elem->opkt,
					    elem->shift,
					    elem->shift > 1 ? "s" : "");
				emit_string(e, "#####\n");
				pke_print(e, pke, ">> ");
				emit_string(e, "\n");
			} else if (!ck_report_reorder(pd, elem, e)) {
				emit_string(e, "#####\n");
				emit_format(e, "# INSERT packet\n",
					    elem->c+1);
				emit_string(e, "#####\n");
				pke_print(e, pke, "++ ");
				emit_string(e, "\n");
			}
			break;

		case MODIFY:
			emit_string(e, "#####\n");
			emit_format(e, "# MODIFY packet %lu\n", elem->r+1);
			emit_string(e, "#####\n");
			mod_pkt_report(&pd->before.pkts[elem->r], elem->r+1, 
				       &pd->after.pkts[elem->c], elem->c+1, e);
			emit_string(e, "\n");
			break;
		}

		elem = elem->next;
		abort_unless(elem != NULL);
	}
}


static void openfile(const char *fn, FILE **fpp, const char **fnp)
{
	abort_unless(fn && fpp && fnp);
	*fnp = fn;
	if (strcmp(fn, "-") == 0) {
		*fpp = stdin;
		*fnp = "<standard input>";
	} else {
		*fpp = fopen(fn, "r");
		if (*fpp == NULL)
			errsys("unable to open file '%s'", fn);
	}
}


int main(int argc, char *argv[])
{
	struct pdiff pd;
	FILE *f1;
	FILE *f2;
	const char *f1n;
	const char *f2n;
	struct file_emitter fe;

	parse_args(argc, argv);

	fdiff_init(&Fdiff);
	hdiff_init(&Hdiff);
	file_emitter_init(&fe, stdout);
	register_std_proto();
	pkb_init_pools(128);

	openfile(filename1, &f1, &f1n);
	openfile(filename2, &f2, &f2n);

	pdiff_load(&pd, f1, f1n, f2, f2n);
	pdiff_compare(&pd);
	pdiff_report(&pd, (struct emitter *)&fe);
	pdiff_clear(&pd);

	fdiff_free(&Fdiff);

	return 0;
}
