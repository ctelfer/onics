#include "netvm_prog.h"
#include <cat/pack.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>


int nvmp_validate(struct netvm_program *prog, struct netvm *vm)
{
	uint i;
	struct netvm_segdesc *sd;
	struct netvm_meminit *mi;

	abort_unless(vm && prog);

	if (prog->ninst < 1)
		return -1;

	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		if ((prog->sdescs[i].perms & ~NETVM_SEG_PMASK) != 0)
			return -1;
	if ((prog->ninits > 0) && (prog->inits == NULL))
		return -1;
	for (i = 0; i < prog->ninits; ++i) {
		mi = &prog->inits[i];
		if (mi->segnum >= NETVM_MAXMSEGS)
			return -1;
		if (vm->msegs[mi->segnum].base == NULL)
			return -1;
		sd = &prog->sdescs[mi->segnum];
		/* check for overflow */
		if (UINT_MAX - mi->off < mi->val.len)
			return -1;
		if (mi->off + mi->val.len > sd->len)
			return -1;
	}
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		if ((prog->cpreqs[i] != NETVM_CPT_NONE) && 
		    (vm->coprocs[i]->type != prog->cpreqs[i]))
			return -1;
	netvm_set_code(vm, prog->inst, prog->ninst);
	netvm_set_matchonly(vm, prog->matchonly);
	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		vm->msegs[i].perms = prog->sdescs[i].perms;
	if (netvm_validate(vm) < 0)
		return -1;

	/* Clean up */
	netvm_set_code(vm, NULL, 0);
	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		vm->msegs[i].perms = 0;

	return 0;
}


void nvmp_init_mem(struct netvm_program *prog, struct netvm *vm)
{
	int i;
	struct netvm_mseg *ms;
	struct netvm_meminit *mi;
	struct netvm_segdesc *sd;

	abort_unless(prog && vm);

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog->sdescs[i];
		ms = &vm->msegs[i];
		abort_unless(sd->len <= ms->len);
		ms->perms = sd->perms;
	}

	abort_unless(prog->ninits == 0 || prog->inits != NULL);

	mi = prog->inits;
	for (i = 0; i < prog->ninits; ++i, ++mi) {
		abort_unless(mi->val.len <= UINT_MAX - mi->off);
		abort_unless(mi->val.len + mi->off <= ms->len);
		abort_unless(mi->segnum < NETVM_MAXMSEGS);
		ms = &vm->msegs[mi->segnum];
		memmove(ms->base + mi->off, mi->val.data, mi->val.len);
	}
}


int nvmp_exec(struct netvm_program *prog, struct netvm *vm, uint64_t *vmrv)
{
	abort_unless(prog && vm);
	netvm_set_code(vm, prog->inst, prog->ninst);
	netvm_set_matchonly(vm, prog->matchonly);
	netvm_restart(vm);
	return netvm_run(vm, -1, vmrv);
}


#define NVMP_MAGIC 0x4E564D50

/*
 * NetVM Program file format: 
 *
 * All multibyte fields are stored big endian.
 * For simplicity, each base field is a 32-bit unsigned integer.
 *  -- 0 -- Magic (0x4E564D50 "NVMP")
 *  -- 1 -- matchonly
 *  -- 2 -- number of instructions
 *  -- 3 -- number of co-processor requirements
 *  -- 4 -- number of segment sections
 *  -- <# instr> * 8 bytes --  instructions
 *  -- <# cpreqs> * 12 bytes --  coprocessor requirements
 *  -- <# segs> -- segment sections
 *
 *  Instruction format:
 *    opcode[1] x[1] y[1] z[1] w[4]
 *
 *  Co Processor requirement format:
 *    cpi[4] cpt[8]
 *
 *  Segment format:
 *    segnum[4] len[4] perms[4]
 */


int nvmp_read(struct netvm_program *prog, FILE *infile, int *eret)
{
	byte_t buf[20];
	struct netvm_segdesc *sd;
	struct netvm_inst *ni;
	uint i;
	ulong magic, matchonly, ninst, ncp, nseg;
	ulong cpi;
	ulonglong cpt;
	ulong segnum, seglen, perms;
	int e = NVMP_RDE_OK;

	abort_unless(prog);
	memset(prog, 0, sizeof(prog));
	/* redundant but explicit */
	prog->ninst = 0;
	prog->inst = NULL;
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd)
		sd->perms = 0;
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;

	if (fread(buf, 1, 20, infile) < 20) {
		e = NVMP_RDE_RUNTHDR;
		goto err;
	}

	/* Read header */
	unpack(buf, 20, "wwwww", &magic, &matchonly, &ninst, &ncp, &nseg);
	if (magic != NVMP_MAGIC) {
		e = NVMP_RDE_BADMAGIC;
		goto err;
	}
	if (ninst > UINT_MAX) {
		e = NVMP_RDE_BADNINST;
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

	prog->matchonly = matchonly;

	/* Read instructions */
	prog->inst = malloc(sizeof(struct netvm_inst) * ninst);
	if (prog->inst == NULL) {
		e = NVMP_RDE_OOMEM;
		goto err;
	}
	prog->ninst = ninst;
	for (i = 0, ni = prog->inst; i < ninst; ++i, ++ni) {
		uchar op, x, y, z;
		ulong w;
		if (fread(buf, 1, 8, infile) < 8) {
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
		if (fread(buf, 1, 12, infile) < 12) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, 12, "wj", &cpi, &cpt);
		if (cpi >= NETVM_MAXCOPROC) {
			e = NVMP_RDE_BADCPI;
			goto err;
		}
		prog->cpreqs[cpi] = cpt;
	}

	for (i = 0; i < nseg; ++i) {
		if (fread(buf, 1, 12, infile) < 12) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, 16, "www", &segnum, &seglen, &perms);
		if (segnum >= NETVM_MAXCOPROC) {
			e = NVMP_RDE_BADSEGN;
			goto err;
		}
		if ((perms & ~(ulong)NETVM_SEG_PMASK) != 0) {
			e = NVMP_RDE_BADSEGP;
			goto err;
		}
		if (seglen > UINT_MAX) {
			e = NVMP_RDE_BADSEGL;
			goto err;
		}
		sd = &prog->sdescs[segnum];
		sd->len = seglen;
		sd->perms = perms;
	}

	if (fread(buf, 1, 1, infile) > 0) {
		e = NVMP_RDE_TOOBIG;
		goto err;
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
	int ncp, nseg;
	struct netvm_segdesc *sd;
	byte_t buf[20];
	struct netvm_inst *ni;
	uint i;

	abort_unless(prog);

	ncp = 0;
	nseg = 0;
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd)
		if (sd->perms != 0)
			++nseg;
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		if (prog->cpreqs[i] != NETVM_CPT_NONE)
			++ncp;

	/* Write header */
	pack(buf, sizeof(buf), "wwwww",
	     (ulong)NVMP_MAGIC, (ulong)prog->matchonly, (ulong)prog->ninst, 
	     (ulong)ncp, (ulong)nseg);

	/* write instructions */
	if (fwrite(buf, 1, 20, outfile) < 20)
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
		if (fwrite(buf, 1, 12, outfile) < 12)
			return -1;
	}

	/* write segment descriptors */
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd) {
		if (sd->perms == 0)
			continue;
		pack(buf, sizeof(buf), "www", (ulong)i, (ulong)sd->len,
		     (ulong)sd->perms);
		if (fwrite(buf, 1, 16, outfile) < 16)
			return -1;
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
}

