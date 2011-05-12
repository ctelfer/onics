#include "netvm_rt.h"
#include "pktbuf.h"
#include <cat/pack.h>
#include <cat/stduse.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>


int nvmp_validate(struct netvm_program *prog, struct netvm *vm)
{
	int i;
	struct netvm_segdesc *sd;

	abort_unless(vm && prog);

	if (prog->ninst < 1)
		return -1;

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog->sdescs[i];
		if (sd->len < sd->init.len)
			return -1;
		if (sd->len < vm->msegs[i].len)
			return -1;
		if (sd->len > 0 && vm->msegs[i].base == NULL)
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
	struct netvm_segdesc *sd;

	abort_unless(prog && vm);

	ms = &vm->msegs[0];
	sd = &prog->sdescs[0];
	for (i = 0; i < NETVM_MAXMSEGS; ++i, ++ms, ++sd) {
		abort_unless(sd->init.len <= ms->len);
		ms->perms = sd->perms;
		memmove(ms->base, sd->init.data, sd->init.len);
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
 *  -- <remainder> -- segment sections
 *
 *  Instruction format:
 *    opcode[1] x[1] y[1] z[1] w[4]
 *
 *  Co Processor requirement format:
 *    cpi[4] cpt[8]
 *
 *  Segment format:
 *    segnum[4] len[4] perms[4] ilen[4] <ilen bytes rouded to a multiple of 4>
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
	ulong segnum, seglen, perms, ilen;
	int e = NVMP_RDE_OK;

	abort_unless(prog);
	memset(prog, 0, sizeof(prog));
	/* redundant but explicit */
	prog->ninst = 0;
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
		if (fread(buf, 1, 8, infile) < 8) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, 8, "bbbbw", &ni->op, &ni->x, &ni->y, &ni->z,
		       &ni->w);
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
		if (fread(buf, 1, 16, infile) < 12) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		unpack(buf, 16, "wwww", &segnum, &seglen, &perms,
		       &ilen);
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
		if (ilen > seglen) {
			e = NVMP_RDE_BADSEGI;
			goto err;
		}
		sd = &prog->sdescs[segnum];
		sd->len = seglen;
		sd->perms = perms;
		sd->init.len = ilen;
		sd->init.data = malloc(ilen);
		if (sd->init.data == NULL) {
			e = NVMP_RDE_OOMEM;
			goto err;
		}
		if (fread(sd->init.data, 1, ilen, infile) < ilen) {
			e = NVMP_RDE_TOOSMALL;
			goto err;
		}
		if ((ilen & 0x3) != 0) {
			ilen = 4 - (ilen & 0x3);
			if (fread(buf, 1, ilen, infile) < ilen) {
				e = NVMP_RDE_TOOSMALL;
				goto err;
			}
		}
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
	uint x;

	abort_unless(prog);

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
		pack(buf, sizeof(buf), "wwww", (ulong)i, (ulong)sd->len,
		     (ulong)sd->perms, (ulong)sd->init.len);
		if (fwrite(buf, 1, 16, outfile) < 16)
			return -1;
		if (sd->init.len > 0) {
			abort_unless(sd->init.data != NULL);
			if (fwrite(sd->init.data, 1, sd->init.len, outfile) < 
			    sd->init.len)
				return -1;
			if ((sd->init.len & 0x3) != 0) {
				x = 4 - (sd->init.len & 0x3);
				memset(buf, 0, 3);
				if (fwrite(buf, 1, x, outfile) < x)
					return -1;
			}
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
		sd->init.len = 0;
		if (sd->init.data != NULL) {
			free(sd->init.data);
			sd->init.data = NULL;
		}
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;
}


void nvmmrt_init(struct netvm_mrt *mrt, uint ssz, uint msz,
		 struct netvm_rt_io *io)
{
	uint64_t *stk;
	byte_t *mem;

	abort_unless(mrt && ssz > 0 && io);

	stk = ecalloc(ssz, sizeof(uint64_t));
	if (msz > 0)
		mem = ecalloc(msz, sizeof(byte_t));
	else
		mem = NULL;

	netvm_init(&mrt->vm, stk, ssz);
	mrt->io = io;
	mrt->begin = NULL;
	mrt->end = NULL;
	mrt->pktprogs = clist_new_list(&estdmm,
				       sizeof(struct netvm_matchedprog));
	mrt->eprog = NULL;
}


int nvmmrt_set_begin(struct netvm_mrt *mrt, struct netvm_program *prog)
{
	abort_unless(mrt && prog);

	if (nvmp_validate(prog, &mrt->vm) < 0)
		return -1;

	mrt->begin = prog;

	return 0;
}


int nvmmrt_set_end(struct netvm_mrt *mrt, struct netvm_program *prog)
{
	abort_unless(mrt && prog);

	if (nvmp_validate(prog, &mrt->vm) < 0)
		return -1;

	mrt->end = prog;

	return 0;
}


int nvmmrt_add_pktprog(struct netvm_mrt *mrt, struct netvm_program *match,
		       struct netvm_program *action)
{
	struct netvm_matchedprog mp;

	abort_unless(mrt && mrt->pktprogs && action && match);
	abort_unless(match->matchonly);

	if (nvmp_validate(match, &mrt->vm) < 0)
		return -1;
	if (nvmp_validate(action, &mrt->vm) < 0)
		return -1;

	mp.match = match;
	mp.action = action;
	clist_enqueue(mrt->pktprogs, &mp);

	return 0;
}


int nvmmrt_execute(struct netvm_mrt *mrt)
{
	struct pktbuf *pkb;
	struct netvm_matchedprog *mprog;
	int i, rv, send;
	uint64_t rc;
	struct clist_node *cln;

	abort_unless(mrt);


	if (mrt->begin) {
		nvmp_init_mem(mrt->begin, &mrt->vm);
		if (nvmp_exec(mrt->begin, &mrt->vm, NULL) < 0)
			return -1;
	}

	while ((pkb = (*mrt->io->pktin)(mrt->io->inctx))) {
		netvm_load_pkt(&mrt->vm, pkb, 0);

		send = 1;
		clist_for_each(cln, mrt->pktprogs) {
			mprog = cln_dptr(cln);
			if ((rv=nvmp_exec(mprog->match, &mrt->vm, &rc)) < 0)
				return -1;
			if (!rc)
				continue;
			/* clear all packets on an error */
			if ((rv=nvmp_exec(mprog->action, &mrt->vm, &rc)) < 0) {
				for (i = 0; i < NETVM_MAXPKTS; ++i)
					netvm_clr_pkt(&mrt->vm, i, 0);
				continue;
			}
			if (rv > 0) {
				if (rv > 0)
					send = 0;
				if (rv == 2)
					break;
			}
		}
		if (send) {
			for (i = 0; i < NETVM_MAXPKTS; ++i) {
				pkb = netvm_clr_pkt(&mrt->vm, i, 1);
				if (pkb)
					(*mrt->io->pktout)(pkb,mrt->io->outctx);
			}
		} else {
			netvm_clr_pkt(&mrt->vm, 0, 0);
		}
	}

	for (i = 0; i < NETVM_MAXPKTS; ++i)
		netvm_clr_pkt(&mrt->vm, i, 0);

	if (mrt->end) {
		if (nvmp_exec(mrt->end, &mrt->vm, NULL) < 0)
			return -1;
	}

	return 0;
}


void nvmmrt_release(struct netvm_mrt *mrt, void (*progfree) (void *))
{
	struct clist_node *cln;
	struct netvm_matchedprog *mprog;

	abort_unless(mrt);

	if (progfree) {
		(*progfree)(mrt->begin);
		(*progfree)(mrt->end);
		clist_for_each(cln, mrt->pktprogs) {
			mprog = cln_dptr(cln);
			(*progfree)(mprog->match);
			(*progfree)(mprog->action);
		}
	}

	clist_free_list(mrt->pktprogs);
	memset(mrt, 0, sizeof(*mrt));
}


static struct pktbuf *stdio_rdpkt(void *unused)
{
	struct pktbuf *pkb;
	errno = 0;
	if (pkb_file_read(&pkb, stdin) < 0)
		return NULL;
	return pkb;
}


static int stdio_sendpkt(void *unused, struct pktbuf *pkb)
{
	errno = 0;
	return pkb_fd_write(pkb, 1);
}


struct netvm_rt_io netvm_rt_io_stdio = {
	&stdio_rdpkt, NULL, &stdio_sendpkt, NULL
};
