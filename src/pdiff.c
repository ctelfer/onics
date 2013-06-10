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

#include "ns.h"
#include "pktbuf.h"
#include "stdproto.h"
#include "fld.h"


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

struct fdiff;

double Drop_cost = 2;
double Insert_cost = 5;
double Infinity = 1e20;
struct fdiff Fdiff;


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
	double			cost;
	struct chgpath *	next;	/* filled in after backtrace */
};


struct cpmatrix {
	struct chgpath **	elems;
	ulong			nrows;
	ulong			ncols;
};

#define cpm_elem(cpm, r, c) (&(cpm)->elems[r][c])



/* packet difference comparitor */
struct pdiff {
	struct pktarr 		before;
	struct pktarr 		after;
	ulong			nb;
	ulong			na;
	struct cpmatrix		cpm;
};


/* field differentce comparitor */
struct fdiff {
	struct npf_list		before;
	struct npf_list		after;
	ulong			nb;
	ulong			na;
	struct cpmatrix		cpm;
	ulong			cpm_maxr;
	ulong			cpm_maxc;
};


enum {
	PPF_PROTO,
	PPF_FIELD,
};

typedef int (*pkbpr_filter_f)(int type, void *unit, void *ctx);

static int femit(struct emitter *e, struct ns_elem *elem, struct pktbuf *pkb,
		 struct prparse *prp)
{
	int rv;
	char line[256];
	struct raw lr = { sizeof(line), (void *)line };

	rv = ns_tostr(elem, pkb->buf, prp, &lr);
	if (rv < 0)
		return -1;

	/* sanity */
	line[sizeof(line)-1] = '\0';

	if (emit_string(e, line) < 0)
		return -1;

	if (emit_char(e, '\n') < 0)
		return -1;

	return 0;
}


static int off_is_valid(struct ns_elem *elem, struct prparse *prp)
{
	int oi;
	if (elem->type == NST_NAMESPACE) {
		oi = ((struct ns_namespace *)elem)->oidx;
	} else if (elem->type == NST_PKTFLD) {
		oi = ((struct ns_pktfld*)elem)->oidx;
	} else {
		return 0;
	}
	return prp_off_valid(prp, oi);
}


static int print_fields(struct emitter *e, const char *pfx, struct pktbuf *pkb,
			struct prparse *prp, struct ns_namespace *ns,
			pkbpr_filter_f *f, void *fctx)
{
	int i;
	struct ns_elem *elem;
	struct ns_namespace *subns;

	abort_unless(e && pkb && prp);
	if (ns == NULL) {
		ns = ns_lookup_by_prid(prp->prid);
		if (ns == NULL)
			return 0;
	} else {
		if (!off_is_valid((struct ns_elem *)ns, prp))
			return 0;
	}

	if (pfx != NULL && emit_string(e, pfx) < 0)
		return -1;

	if (femit(e, (struct ns_elem *)ns, pkb, prp) < 0)
		return -1;

	for (i = 0; i < ns->nelem; ++i) {
		elem = ns->elems[i];

		if (elem == NULL)
			break;

		if (!off_is_valid(elem, prp))
			continue;

		if ((f != NULL) && (*f)(PPF_FIELD, elem, fctx))
			continue;

		if (pfx != NULL && emit_string(e, pfx) < 0)
			return -1;

		if (femit(e, elem, pkb, prp) < 0)
			return -1;

		if (elem->type == NST_NAMESPACE) {
			subns = (struct ns_namespace *)elem;
			if (print_fields(e, pfx, pkb, prp, subns, f, fctx) < 0)
				return -1;
		}
	}

	return 0;
}


int pkb_print(struct emitter *e, struct pktbuf *pkb, const char *pfx,
	      pkbpr_filter_f *f, void *fctx)
{
	struct prparse *prp;

	if (e == NULL || pkb == NULL)
		return -1;

	prp_for_each(prp, &pkb->prp) {
		if ((f != NULL) && (*f)(PPF_PROTO, prp, fctx))
			continue;
		if (print_fields(e, pfx, pkb, prp, NULL, f, fctx) < 0)
			return -1;
	}

	return 0;
}


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
		if (pkb_parse(pa->pkts[pa->npkts].pkt) < 0)
			err("unable to parse packet %lu\n", pa->npkts+1);
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


static void cpm_ealloc(struct cpmatrix *cpm, ulong nr, ulong nc)
{
	struct chgpath *cpe;
	struct chgpath **rp;
	ulong i;

	abort_unless(nr > 0 || nc > 0 || 
		     ULONG_MAX / sizeof(struct chgpath) / nc <= nr);

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


void fdiff_init(struct fdiff *fd)
{
	memset(fd, 0, sizeof(*fd));
	fd->cpm_maxr = 0;	/* explicit */
	fd->cpm_maxc = 0;	/* explicit */
}


void fdiff_load(struct fdiff *fd, struct pktbuf *before, ulong bpn,
	        struct pktbuf *after, ulong apn)
{
	if (npfl_load(&fd->before, &before->prp, before->buf) < 0)
		err("out of mem loading field array for pkt %lu in stream 1",
		    bpn);

	if (npfl_fill_gaps(&fd->before))
		err("out of mem filling gaps pkt %lu in stream 1", bpn);

	if (npfl_load(&fd->after, &after->prp, after->buf) < 0)
		err("out of mem loading field array for pkt %lu in stream 2",
		    apn);

	if (npfl_fill_gaps(&fd->after))
		err("out of mem filling gaps pkt %lu in stream 2", apn);

	fd->nb = npfl_length(&fd->before);
	fd->na = npfl_length(&fd->after);

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
		  
		  
void fdiff_clear(struct fdiff *fd)
{
	npfl_cache(&fd->before);
	npfl_cache(&fd->after);
}
		  
		  
void fdiff_free(struct fdiff *fd)
{
	npfl_cache(&fd->before);
	npfl_cache(&fd->after);
	cpm_clear(&fd->cpm);
	fd->cpm.nrows = 0;
	fd->cpm.ncols = 0;
}
		  

static void getmincost(struct chgpath *p, double icost, double dcost,
		       double mcost, int maction)
{
	/* bias towards modify */
	if (icost < dcost) {
		if (icost < mcost) {
			p->action = INSERT;
			p->cost = icost;
		} else {
			p->action = maction;
			p->cost = mcost;
		}
	} else {
		if (dcost < mcost) {
			p->action = DROP;
			p->cost = dcost;
		} else {
			p->action = maction;
			p->cost = mcost;
		}
	}
}


double fdiff_cost(struct fdiff *fd)
{
	return cpm_elem(&fd->cpm, fd->nb, fd->na)->cost;
}


void fdiff_compare(struct fdiff *fd)
{
	ulong i, j;
	int maction;
	double mcost;
	double icost;
	double dcost;
	struct cpmatrix *cpm = &fd->cpm;
	struct chgpath *ipos, *dpos, *mpos;
	struct npf_list *rnpfl = &fd->before;
	struct npf_list *cnpfl = &fd->after;
	struct npfield *rnpf;
	struct npfield *cnpf;
	double drop_bit_cost;
	double ins_bit_cost;
	double mod_bit_cost;

	cpm_elem(cpm, 0, 0)->action = DONE;
	cpm_elem(cpm, 0, 0)->cost = 0;

	/* 
	 * Each drop costs an amount proportional to the # of bits
	 * being dropped in from the packet.  Similarly, each insert
	 * costs an amount proportional to the # of bits inserted.
	 */
	drop_bit_cost = Drop_cost / (double)(prp_plen(rnpfl->plist) * 8);
	ins_bit_cost = Insert_cost / (double)(prp_plen(cnpfl->plist) * 8);
	mod_bit_cost = (drop_bit_cost + ins_bit_cost);

	rnpf = npfl_first(rnpfl);
	for (i = 1; i < cpm->nrows; ++i) {
		dpos = cpm_elem(cpm, i, 0);
		dpos->action = DROP;
		dpos->cost = cpm_elem(cpm, i-1, 0)->cost + 
			     rnpf->len * drop_bit_cost;
		rnpf = npf_next(rnpf);
	}

	cnpf = npfl_first(cnpfl);
	for (i = 1; i < cpm->ncols; ++i) {
		ipos = cpm_elem(cpm, 0, i);
		ipos->action = INSERT;
		ipos->cost = cpm_elem(cpm, 0, i-1)->cost + 
			     cnpf->len * ins_bit_cost;
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
				mcost = mpos->cost + mod_bit_cost * rnpf->len;
				maction = MODIFY;
			} else {
				mcost = Infinity;
				maction = MODIFY;
			}

			icost = ipos->cost + ins_bit_cost * rnpf->len;
			dcost = dpos->cost + drop_bit_cost * cnpf->len;

			getmincost(cpm_elem(cpm, i, j), icost, dcost, mcost,
				   maction);
			cnpf = npf_next(cnpf);
		}
		rnpf = npf_next(rnpf);
	}
}


double pkt_cmp(struct pktent *pe1, ulong pe1n, struct pktent *pe2, ulong pe2n)
{
	double cost;

	if (memcmp(pe1->hash, pe2->hash, sizeof(pe1->hash)) == 0)
		return 0.0;

	fdiff_load(&Fdiff, pe1->pkt, pe1n, pe2->pkt, pe2n);
	fdiff_compare(&Fdiff);
	cost = fdiff_cost(&Fdiff);
	fdiff_clear(&Fdiff);

	return cost;
}


void pdiff_backtrace(struct pdiff *pd)
{
	ulong r = pd->before.npkts;
	ulong c = pd->after.npkts;
	struct cpmatrix *cpm = &pd->cpm;
	struct chgpath *elem, *prev;

	abort_unless(r == cpm->nrows - 1);
	abort_unless(c == cpm->ncols - 1);

	elem = cpm_elem(cpm, r, c);
	while (elem->action != DONE) {
		abort_unless(r < cpm->nrows && c < cpm->ncols);

		switch(elem->action) {
		case PASS: 	r -= 1; c -= 1; break;
		case DROP: 	r -= 1; break;
		case INSERT: 	c -= 1; break;
		case MODIFY:	r -= 1; c -= 1; break;
		case SWAP:	r -= 1; c -= 1; abort_unless(0); break;
		default:	abort_unless(0);
		}

		prev = cpm_elem(cpm, r, c);
		prev->next = elem;
		elem = prev;
	}
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
	struct pktarr *rpkts = &pd->before;
	struct pktarr *cpkts = &pd->after;

	cpm_elem(cpm, 0, 0)->action = DONE;
	cpm_elem(cpm, 0, 0)->cost = 0;

	for (i = 1; i < cpm->nrows; ++i) {
		dpos = cpm_elem(cpm, i, 0);
		dpos->action = DROP;
		dpos->cost = i * Drop_cost;
	}

	for (i = 1; i < cpm->ncols; ++i) {
		ipos = cpm_elem(cpm, 0, i);
		ipos->action = INSERT;
		ipos->cost = i * Insert_cost;
	}


	for (i = 1; i < cpm->nrows; ++i) {
		for (j = 1; j < cpm->ncols; ++j) {
			ipos = cpm_elem(cpm, i, j-1);
			dpos = cpm_elem(cpm, i-1, j);
			mpos = cpm_elem(cpm, i-1, j-1);

			mcost = pkt_cmp(&rpkts->pkts[i-1], i,
					&cpkts->pkts[j-1], j);
			maction = (mcost == 0.0) ? PASS : MODIFY;
			mcost += mpos->cost;
			icost = ipos->cost + Insert_cost;
			dcost = dpos->cost + Drop_cost;

			getmincost(cpm_elem(cpm, i, j), icost, dcost, mcost,
				   maction);
		}
	}

	pdiff_backtrace(pd);
}


void pdiff_report(struct pdiff *pd, struct emitter *e)
{
	ulong r = 0;
	ulong c = 0;
	struct cpmatrix *cpm = &pd->cpm;
	struct chgpath *elem, *next;
	struct pktbuf *pkb;

	elem = cpm_elem(cpm, 0, 0);
	while (elem->next != NULL) {
		next = elem->next;
		switch (next->action) {
		case PASS: 
			r += 1; 
			c += 1;
			break;

		case DROP:
			emit_format(e, 
				    "DROP packet %lu from the original "
			 	    "stream\n", r+1);
			pkb = pd->before.pkts[r].pkt;
			pkb_print(e, pkb, "\t-", NULL, NULL);
			r += 1;
			break;

		case INSERT:
			emit_format(e,
				    "INSERT packet %lu in the result "
				    "stream\n", c+1);
			pkb = pd->after.pkts[c].pkt;
			pkb_print(e, pkb, "\t+", NULL, NULL);
			c += 1;
			break;

		case MODIFY:
			emit_format(e,
				    "MODIFY packet %lu from the original "
				    "stream to become packet %lu from the"
				    " new stream\n", r+1, c+1);
			/* TODO: detailed modification printing */
			r += 1; 
			c += 1;
			break;

		case SWAP:
			emit_format(e,
				    "SWAP packet %lu from the original "
				    "stream with the packet %lu\n", r, r+1);
			pkb = pd->before.pkts[r].pkt;
			pkb_print(e, pkb, "\t<", NULL, NULL);
			pkb = pd->before.pkts[r-1].pkt;
			pkb_print(e, pkb, "\t>", NULL, NULL);
			r += 1;
			c += 1;
			break;
		}

		elem = next;
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

	if (argc < 3 || strcmp(argv[1], "-h") == 0)
		err("usage: %s FILE1 FILE2");

	fdiff_init(&Fdiff);
	file_emitter_init(&fe, stdout);
	register_std_proto();
	pkb_init(128);

	openfile(argv[1], &f1, &f1n);
	openfile(argv[2], &f2, &f2n);

	pdiff_load(&pd, f1, f1n, f2, f2n);
	pdiff_compare(&pd);
	pdiff_report(&pd, (struct emitter *)&fe);
	pdiff_clear(&pd);

	fdiff_free(&Fdiff);

	return 0;
}
