#include "netvm_prog.h"
#include <cat/pack.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>


STATIC_BUG_ON(uint_larger_than_32_bits, sizeof(uint32_t) < sizeof(uint));


static void install_mseg(struct netvm *vm, struct netvm_program *prog,
		         struct netvm_segdesc save[NETVM_MAXMSEGS])
{
	int i;
	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		save[i].len = vm->msegs[i].len;
		vm->msegs[i].len = prog->sdescs[i].len;
		save[i].perms = vm->msegs[i].perms;
		vm->msegs[i].perms = prog->sdescs[i].perms;
	}

}


static void restore_mseg(struct netvm *vm, 
		         struct netvm_segdesc save[NETVM_MAXMSEGS])
{
	int i;
	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		vm->msegs[i].len = save[i].len;
		vm->msegs[i].perms = save[i].perms;
	}

}


int nvmp_ep_is_set(struct netvm_program *prog, int ep)
{
	abort_unless(prog && ep >= 0 && ep < NVMP_EP_NUMEP);
	return prog->eps[ep] != NVMP_EP_INVALID;
}


int nvmp_validate(struct netvm_program *prog, struct netvm *vm)
{
	uint i;
	int rv = 0;
	struct netvm_segdesc *sd;
	struct netvm_meminit *mi;
	struct netvm_mseg *ms;
	struct netvm_segdesc msave[NETVM_MAXMSEGS];

	abort_unless(vm && prog);

	if (prog->ninst < 1)
		return NETVM_ERR_PROG;

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog->sdescs[i];
		ms = &vm->msegs[i];
		if (((sd->perms & ~NETVM_SEG_PMASK) != 0) ||
		    ((sd->perms & ms->perms) != sd->perms) ||
		    (sd->len > ms->len))
			return NETVM_ERR_PROG;
	}

	if ((prog->ninits > 0) && (prog->inits == NULL))
		return -1;
	for (i = 0; i < prog->ninits; ++i) {
		mi = &prog->inits[i];
		if (mi->segnum >= NETVM_MAXMSEGS)
			return NETVM_ERR_PROG;
		if (vm->msegs[mi->segnum].base == NULL)
			return NETVM_ERR_PROG;
		sd = &prog->sdescs[mi->segnum];
		/* check for overflow */
		if (UINT_MAX - mi->off < mi->val.len)
			return NETVM_ERR_PROG;
		if (mi->off + mi->val.len > sd->len)
			return NETVM_ERR_PROG;
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		if ((prog->cpreqs[i] != NETVM_CPT_NONE) && 
		    (vm->coprocs[i]->type != prog->cpreqs[i]))
			return NETVM_ERR_BADCP;

	netvm_set_code(vm, prog->inst, prog->ninst);
	netvm_set_matchonly(vm, prog->matchonly);
	install_mseg(vm, prog, msave);

	rv = netvm_validate(vm);

	/* Clean up */
	netvm_set_code(vm, NULL, 0);
	restore_mseg(vm, msave);

	return rv;
}


void nvmp_init_mem(struct netvm_program *prog, struct netvm *vm)
{
	int i;
	struct netvm_mseg *ms;
	struct netvm_meminit *mi;

	abort_unless(prog && vm);

	abort_unless(prog->ninits == 0 || prog->inits != NULL);

	mi = prog->inits;
	for (i = 0; i < prog->ninits; ++i, ++mi) {
		abort_unless(mi->segnum < NETVM_MAXMSEGS);
		ms = &vm->msegs[mi->segnum];
		abort_unless(mi->val.len <= UINT_MAX - mi->off);
		abort_unless(mi->val.len + mi->off <= ms->len);
		memmove(ms->base + mi->off, mi->val.data, mi->val.len);
	}
}


int nvmp_exec(struct netvm_program *prog, int ep, struct netvm *vm, int maxc,
	      uint64_t *vmrv)
{
	int rv;
	struct netvm_segdesc msave[NETVM_MAXMSEGS];

	abort_unless(prog && vm && ep >= 0 && ep < NVMP_EP_NUMEP);
	netvm_set_code(vm, prog->inst, prog->ninst);
	netvm_set_matchonly(vm, prog->matchonly);
	netvm_restart(vm);
	netvm_set_pc(vm, prog->eps[ep]);
	install_mseg(vm, prog, msave);
	rv = netvm_run(vm, maxc, vmrv);
	restore_mseg(vm, msave);

	return rv;
}


#define NETVM_PROG_EXT_EP_INVALID 0xFFFFFFFF


int nvmp_read(struct netvm_program *prog, FILE *infile, int *eret)
{
	byte_t buf[NVMP_HLEN];
	struct netvm_segdesc *sd;
	struct netvm_inst *ni;
	struct netvm_meminit *mi;
	uint i;
	byte_t version, matchonly, p1, p2;
	ulong magic, ninst, ncp, nseg, nmi, milen;
	ulong sep, pep, eep;
	ulong cpi;
	ulonglong cpt;
	ulong segnum, off, len, perms;
	size_t ilen;
	int e = NVMP_RDE_OK;

	abort_unless(prog);
	memset(prog, 0, sizeof(prog));
	/* redundant but explicit */
	prog->ninst = 0;
	prog->inst = NULL;
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd) {
		sd->perms = 0;
		sd->len = 0;
	}
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;

	if (fread(buf, 1, NVMP_HLEN, infile) < NVMP_HLEN) {
		e = NVMP_RDE_RUNTHDR;
		goto err;
	}

	/* Read header */
	unpack(buf, sizeof(buf), "wbbbbwwwwwwww", &magic, &version, &matchonly, 
	       &p1, &p2, &ninst, &ncp, &nseg, &nmi, &milen, &sep, &pep, &eep);

	if (sep == NETVM_PROG_EXT_EP_INVALID)
		sep = NVMP_EP_INVALID;
	if (pep == NETVM_PROG_EXT_EP_INVALID)
		pep = NVMP_EP_INVALID;
	if (eep == NETVM_PROG_EXT_EP_INVALID)
		eep = NVMP_EP_INVALID;

	if ((magic != NVMP_MAGIC) || (version != NVMP_V1)) {
		e = NVMP_RDE_BADMAGIC;
		goto err;
	}
	if (ninst > UINT_MAX) {
		e = NVMP_RDE_BADNINST;
		goto err;
	}
	if (((sep != NVMP_EP_INVALID) && (sep >= ninst)) || 
	    ((pep != NVMP_EP_INVALID) && (pep >= ninst)) || 
	    ((eep != NVMP_EP_INVALID) && (eep >= ninst))) {
		e = NVMP_RDE_BADEP;
		goto err;
	}
	if (ncp > NETVM_MAXCOPROC) {
		e = NVMP_RDE_BADNCPI;
		goto err;
	}
	if (nseg > NETVM_MAXMSEGS) {
		e = NVMP_RDE_BADNSEG;
		goto err;
	}
	if (nmi > UINT_MAX) {
		e = NVMP_RDE_MITOTLEN;
		goto err;
	}

	prog->matchonly = matchonly;

	/* Read instructions */
	prog->inst = calloc(sizeof(struct netvm_inst), ninst);
	if (prog->inst == NULL) {
		e = NVMP_RDE_OOMEM;
		goto err;
	}
	prog->ninst = ninst;
	prog->eps[NVMP_EP_START] = sep;
	prog->eps[NVMP_EP_PACKET] = pep;
	prog->eps[NVMP_EP_END] = eep;
	for (i = 0, ni = prog->inst; i < ninst; ++i, ++ni) {
		uchar op, x, y, z;
		ulong w;
		if (fread(buf, 1, NVMP_INSTLEN, infile) < NVMP_INSTLEN) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, 8, "bbbbw", &op, &x, &y, &z, &w);
		ni->op = op;
		ni->x = x;
		ni->y = y;
		ni->z = z;
		ni->w = w;
	}

	/* read coprocessor requirements */
	for (i = 0; i < ncp; ++i) {
		if (fread(buf, 1, NVMP_CPLEN, infile) < NVMP_CPLEN) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, sizeof(buf), "wj", &cpi, &cpt);
		if (cpi >= NETVM_MAXCOPROC) {
			e = NVMP_RDE_BADCPI;
			goto err;
		}
		prog->cpreqs[cpi] = cpt;
	}

	/* read segment descriptors */
	for (i = 0; i < nseg; ++i) {
		if (fread(buf, 1, NVMP_SEGPLEN, infile) < NVMP_SEGPLEN) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, sizeof(buf), "www", &segnum, &len, &perms);
		if (segnum >= NETVM_MAXMSEGS) {
			e = NVMP_RDE_BADSEGN;
			goto err;
		}
		if ((perms & ~(ulong)NETVM_SEG_PMASK) != 0) {
			e = NVMP_RDE_BADSEGP;
			goto err;
		}
		if (len > UINT_MAX) {
			e = NVMP_RDE_BADSEGL;
			goto err;
		}
		sd = &prog->sdescs[segnum];
		sd->len = len;
		sd->perms = perms;
	}


	/* read the memory initializations */
	mi = prog->inits = calloc(sizeof(struct netvm_meminit), nmi);
	if (mi == NULL) {
		e = NVMP_RDE_OOMEM;
		goto err;
	}
	prog->ninits = nmi;
	for (i = 0; i < prog->ninits; ++i) {
		prog->inits[i].val.data = NULL;
		prog->inits[i].val.len = 0;
	}
	for (i = 0; i < nmi; ++i, ++mi) {
		if (milen < NVMP_MIHLEN) {
			e = NVMP_RDE_MITOTLEN;
			goto err;
		}
		if (fread(buf, 1, NVMP_MIHLEN, infile) < NVMP_MIHLEN) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		milen -= NVMP_MIHLEN;
		unpack(buf, sizeof(buf), "www", &segnum, &off, &len);
		if (len > (SIZE_MAX & ~(size_t)3)) {
			e = NVMP_RDE_MILEN;
			goto err;
		}
		if (segnum >= NETVM_MAXMSEGS) {
			e = NVMP_RDE_MISEG;
			goto err;
		}
		sd = &prog->sdescs[segnum];
		if ((off >= sd->len) || (sd->len - off < len)) {
			e = NVMP_RDE_MIOFFLEN;
			goto err;
		}
		ilen = (len + 3) & ~3;
		if (milen < ilen) {
			e = NVMP_RDE_MITOTLEN;
			goto err;
		}
		if (ilen > 0) {
			if ((mi->val.data = malloc(ilen)) == NULL) {
				e = NVMP_RDE_OOMEM;
				goto err;
			}
			if (fread(mi->val.data, 1, ilen, infile) < ilen) {
				e = NVMP_RDE_TOOSMALL;
				goto err;
			}
			memset(mi->val.data + len, 0, ilen - len);
		}
		mi->val.len = len;
		mi->segnum = segnum;
		mi->off = off;
	}


	if (eret != NULL)
		*eret = NVMP_RDE_OK;
	return 0;

err:
	nvmp_clear(prog);
	if (eret != NULL)
		*eret = e;
	return -1;
}


int nvmp_write(struct netvm_program *prog, FILE *outfile)
{
	struct netvm_segdesc *sd;
	struct netvm_meminit *mi;
	byte_t buf[NVMP_HLEN];
	struct netvm_inst *ni;
	uint i;
	ulong ncp = 0, nseg = 0, milen = 0, ilen;
	ulong eps[NVMP_EP_NUMEP];

	abort_unless(prog);

	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd)
		if (sd->perms != 0)
			++nseg;
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		if (prog->cpreqs[i] != NETVM_CPT_NONE)
			++ncp;
	if (ULONG_MAX / NVMP_MIHLEN < prog->ninits)
		return -1;
	milen = NVMP_MIHLEN * prog->ninits;
	for (i = 0; i < prog->ninits; ++i) {
		mi = &prog->inits[i];
		if ((mi->val.len > (SIZE_MAX & ~(size_t)3)) || 
		    (mi->segnum >= NETVM_MAXMSEGS))
			return -1;
		ilen = (mi->val.len + 3) & ~(size_t)3;
		if (ULONG_MAX - milen < ilen)
			return -1;
		milen += ilen;
	}

	for (i = 0; i < NVMP_EP_NUMEP; ++i) {
		if (prog->eps[i] == NVMP_EP_INVALID)
			eps[i] = NETVM_PROG_EXT_EP_INVALID;
		else
			eps[i] = prog->eps[i];
	}

	/* write header */
	pack(buf, sizeof(buf), "wbbbbwwwwwwww",
	     (ulong)NVMP_MAGIC, NVMP_V1, prog->matchonly, 0, 0, 
	     (ulong)prog->ninst, ncp, nseg,
	     (ulong)prog->ninits, milen, eps[0], eps[1], eps[2]);

	/* write instructions */
	if (fwrite(buf, 1, NVMP_HLEN, outfile) < NVMP_HLEN)
		return -1;
	for (i = 0, ni = prog->inst; i < prog->ninst; ++i, ++ni) {
		pack(buf, sizeof(buf), "bbbbw", ni->op, ni->x, ni->y,
		     ni->z, ni->w);
		if (fwrite(buf, 1, 8, outfile) < 8)
			return -1;
	}

	/* write coprocessor requirements */
	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		if (prog->cpreqs[i] == NETVM_CPT_NONE)
			continue;
		pack(buf, sizeof(buf), "wj", (ulong)i,
		     (ulonglong)prog->cpreqs[i]);
		if (fwrite(buf, 1, NVMP_CPLEN, outfile) < NVMP_CPLEN)
			return -1;
	}

	/* write segment descriptors */
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd) {
		if (sd->perms == 0)
			continue;
		pack(buf, sizeof(buf), "www", (ulong)i, (ulong)sd->len,
		     (ulong)sd->perms);
		if (fwrite(buf, 1, NVMP_SEGPLEN, outfile) < NVMP_SEGPLEN)
			return -1;
	}

	/* write memory initializations */
	for (i = 0, mi = prog->inits; i < prog->ninits; ++i, ++mi) {
		pack(buf, sizeof(buf), "www", (ulong)mi->segnum, 
		     (ulong)mi->off, (ulong)mi->val.len);
		if (fwrite(buf, 1, NVMP_MIHLEN, outfile) < NVMP_MIHLEN)
			return -1;
		if (fwrite(mi->val.data, 1, mi->val.len, outfile) < mi->val.len)
			return -1;
		ilen = (mi->val.len + 3) & ~(size_t)3;
		if (ilen > mi->val.len) {
			memset(buf, 0, 4);
			ilen -= mi->val.len;
			if (fwrite(buf, 1, ilen, outfile) < ilen)
				return -1;
		}
	}

	return 0;
}


void nvmp_clear(struct netvm_program *prog)
{
	int i;
	struct netvm_segdesc *sd;

	abort_unless(prog);

	free(prog->inst);
	prog->inst = NULL;
	prog->ninst = 0;

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog->sdescs[i];
		sd->len = 0;
		sd->perms = 0;
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;

	if (prog->ninits != 0) {
		for (i = 0; i < prog->ninits; ++i) {
			abort_unless(prog->inits[i].val.data != NULL);
			free(prog->inits[i].val.data);
			prog->inits[i].val.data = NULL;
			prog->inits[i].val.len = 0;
		}
		free(prog->inits);
	}

	prog->inits = 0;
	prog->inits = NULL;
}

