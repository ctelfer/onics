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

#include "pktbuf.h"


/* 
 * Lets start with the simple version first
 *
 * We're going to use damerau-levenshtein distance because packet reordering
 * is definitely cheaper than packet modifications in a network.  This is
 * actually harder than it sounds since the "alphabet" (unique packets) while
 * not technically infinte might as well be for our purposes. 
 * (2**2**16 effectively)
 *
 * For now, lets use the full NxM matrix to do the computation.  I can use a
 * more memory efficient data structure when I've fully internalized the 
 * algorithm and its implications.  Also, even if we don't keep the full
 * NxM matrix, we can still have NxM space in the form of backtraces and that's
 * what we are really after anyways.
 * 
 * The cost of a substitution is going to be proportional to the amount of 
 * change in the packet.  We might differentiate in reporting the difference
 * between virtually complete substitution and simple editing.
 *
 * Comparison of two packets is nuanced and we need to treat it so.  We may
 * want to not treat certain packet headers (e.g. L2) or fields (e.g. ttl)
 * as significant when comparing packets depending on what we are trying
 * to accomplish.  How fine a granularity is appropriate?  Bit?  Byte?
 * Field?  Header?
 */


ulong Drop_cost = 2;
ulong Insert_cost = 5;


enum {
	DONE,
	PASS,
	DROP,
	INSERT,
	MODIFY,
	SWAP,
};



struct pktent {
	struct pktbuf *		pkt;
	byte_t			hash[32];
};


struct pktarr {
	struct pktent *		pkts;
	ulong			npkts;
	ulong			pasz;
};


struct chgpath {
	int			action;
	ulong			swidx;
	ulong			cost;
};


struct cpmatrix {
	struct chgpath **	elems;
	ulong			nrows;
	ulong			ncols;
};


struct pdiff {
	struct pktarr 		before;
	struct pktarr 		after;
	ulong			nb;
	ulong			na;
	struct cpmatrix		cpm;
};


static void hash_packet(struct pktent *pe)
{
	struct pktbuf *p = pe->pkt;
	sha256(pkb_data(p), pkb_get_len(p), pe->hash);
}


static void pa_readfile(struct pktarr *pa, FILE *fp, const char *fn)
{
	int rv;

	pa->pasz = 16;
	pa->pkts = emalloc(sizeof(struct pktent) * pa->pasz);
	pa->npkts = 0;

	rv = pkb_file_read(&pa->pkts[pa->npkts].pkt, fp);
	while (rv > 0) {
		hash_packet(&pa->pkts[pa->npkts]);
		++pa->npkts;
		if (pa->npkts == pa->pasz) {
			if (pa->pasz * 2 < pa->pasz)
				err("Size overflow\n");
			pa->pasz *= 2;
			pa->pkts = erealloc(pa->pkts, 
					    pa->pasz * sizeof(struct pktent));
		}
		rv = pkb_file_read(&pa->pkts[pa->npkts].pkt, fp);
	}

	if (rv < 0)
		errsys("Error reading packet for file %s", fn);
}


static void pa_clear(struct pktarr *pa)
{
	struct pktent *pe;
	ulong np;

	if (pa == NULL)
		return;

	pe = pa->pkts;
	for (np = 0; np < pa->npkts; ++np) {
		pkb_free(pe->pkt);
		pe++;
	}

	memset(pa->pkts, 0, sizeof(struct pktent) * pa->npkts);
	pa->npkts = 0;
	free(pa->pkts);
	pa->pkts = NULL;
}


static ONICS_INLINE struct chgpath *cpm_elem(struct cpmatrix *cpm, ulong r,
					     ulong c)
{
	abort_unless(cpm && r < cpm->nrows && c < cpm->ncols);
	return &cpm->elems[r][c];
}


static void cpm_ealloc(struct cpmatrix *cpm, ulong nr, ulong nc)
{
	struct chgpath *cpe;
	struct chgpath **rp;
	ulong i;

	abort_unless(nr > 0 || nc > 0 || ULONG_MAX / nc <= nr);

	cpm->nrows = nr;
	cpm->ncols = nc;
	cpm->elems = ecalloc(sizeof(struct chgpath *), nr);
	cpe = ecalloc(sizeof(struct chgpath), nr * nc);

	rp = cpm->elems;
	for (i = 0; i < nr; ++i) {
		*rp++ = cpe;
		cpe += nc;
	}
}


void cpm_clear(struct cpmatrix *cpm)
{
	if (cpm == NULL)
		return;
	free(cpm->elems[0]);
	memset(cpm->elems, 0, sizeof(struct chgpth *) * cpm->nrows);
	free(cpm->elems);
	cpm->elems = NULL;
}


void pdiff_load(struct pdiff *pd, FILE *before, const char *bname, 
		FILE *after, const char *aname)
{
	pa_readfile(&pd->before, before, bname);
	pa_readfile(&pd->after, after, aname);
	pd->nb = pd->before.npkts;
	pd->na = pd->after.npkts;
	cpm_ealloc(&pd->cpm, pd->nb+1, pd->na+1);
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
}


/* TODO:  actually calculate the edit distance between the packets */
ulong pkt_cmp(struct pktent *pe0, struct pktent *pe1)
{
	if (memcmp(pe0->hash, pe1->hash, sizeof(pe0->hash)) == 0)
		return 0;
	else
		return Insert_cost + Drop_cost;
}


static void getmincost(struct chgpath *p, ulong icost, ulong dcost, ulong mcost)
{
	if (icost < dcost) {
		if (icost <= mcost) {
			p->action = INSERT;
			p->cost = icost;
		} else {
			p->action = (mcost == 0) ? PASS : MODIFY;
			p->cost = mcost;
		}
	} else {
		if (dcost <= mcost) {
			p->action = DROP;
			p->cost = dcost;
		} else {
			p->action = (mcost == 0) ? PASS : MODIFY;
			p->cost = mcost;
		}
	}
}


void pdiff_compare(struct pdiff *pd)
{
	ulong i, j;
	ulong mcost;
	ulong icost;
	ulong dcost;
	struct cpmatrix *cpm = &pd->cpm;
	struct chgpath *ins, *drop, *cp2;
	struct pktarr *rpkts = &pd->before;
	struct pktarr *cpkts = &pd->after;

	cpm->elems[0][0].action = DONE;
	cpm->elems[0][0].cost = 0;

	for (i = 1; i < cpm->nrows; ++i) {
		drop = &cpm->elems[i][0];
		drop->action = DROP;
		drop->cost = i * Drop_cost;
	}

	for (i = 1; i < cpm->ncols; ++i) {
		ins = &cpm->elems[0][i];
		ins->action = INSERT;
		ins->cost = i * Insert_cost;
	}


	for (i = 1; i < cpm->nrows; ++i) {
		for (j = 1; j < cpm->ncols; ++j) {
			ins = &cpm->elems[i][j-1];
			drop = &cpm->elems[i-1][j];
			mcost = pkt_cmp(&rpkts->pkts[i-1], &cpkts->pkts[j-1]);

			icost = ins->cost + Insert_cost;
			dcost = drop->cost + Drop_cost;

			getmincost(&cpm->elems[i][j], icost, dcost, mcost);
		}
	}
}


void pdiff_report(struct pdiff *pd, FILE *out)
{
	ulong r = pd->before.npkts;
	ulong c = pd->after.npkts;
	struct cpmatrix *cpm = &pd->cpm;

	abort_unless(r == cpm->nrows - 1);
	abort_unless(c == cpm->ncols - 1);

	while (cpm->elems[r][c].action != DONE) {
		abort_unless(r < cpm->nrows && c < cpm->ncols);

		switch(cpm->elems[r][c].action) {
		case PASS:
			r -= 1;
			c -= 1;
			break;
		case DROP:
			fprintf(out, 
				"DROP packet %lu from the original stream\n",
				r);
			r -= 1;
			break;
		case INSERT:
			c -= 1;
			fprintf(out,
				"INSERT packet %lu in the result stream\n", c);
			break;
		case MODIFY:
			fprintf(out,
				"MODIFY packet %lu from the original stream\n",
				r);
			break;
		case SWAP:
			r -= 1;
			c -= 1;
			/* TODO */
			abort_unless(0);
			break;
		default:
			abort_unless(0);
		}
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

	if (argc < 3 || strcmp(argv[1], "-h") == 0)
		err("usage: %s FILE1 FILE2");

	pkb_init(128);
	openfile(argv[1], &f1, &f1n);
	openfile(argv[2], &f2, &f2n);
	pdiff_load(&pd, f1, f1n, f2, f2n);
	pdiff_compare(&pd);
	pdiff_report(&pd, stdout);
	pdiff_clear(&pd);

	return 0;
}
