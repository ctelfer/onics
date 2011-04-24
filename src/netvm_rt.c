#include "netvm_rt.h"
#include "pktbuf.h"
#include <cat/stduse.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>


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
		if (vm->coprocs[i]->type != prog->cpreqs[i])
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
