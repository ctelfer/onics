#ifndef __netvm_rt_h
#define __netvm_rt_h

#include "netvm.h"
#include "netvm_prog.h"

struct netvm_matchedprog {
	struct netvm_program *	match;
	struct netvm_program *	action;
};


struct netvm_mrt_vmcfg {
	uint			stksz;
	struct netvm_segdesc	sdescs[NETVM_MAXMSEGS];
	struct netvm_coproc *	coprocs[NETVM_MAXCOPROC];
	struct netvm_meminit	*inits;
	uint			ninits;
};

typedef struct pktbuf *(*netvm_pktin_f)(void *ctx);
typedef int (*netvm_pktout_f)(void *ctx, struct pktbuf *pkb);

struct netvm_rt_io {
	netvm_pktin_f		pktin;
	void *			inctx;
	netvm_pktout_f		pktout;
	void *			outctx;
};

extern struct netvm_rt_io netvm_rt_io_stdio;

struct netvm_mrt {
	struct netvm		vm;
	struct netvm_rt_io *	io;
	struct netvm_program *	begin;
	struct netvm_program *	end;
	struct clist *		pktprogs;
};

void nvmmrt_init(struct netvm_mrt *mrt, struct netvm_mrt_vmcfg *cfg,
		 struct netvm_rt_io *io);
int nvmmrt_set_begin(struct netvm_mrt *mrt, struct netvm_program *prog);
int nvmmrt_set_end(struct netvm_mrt *mrt, struct netvm_program *prog);
int nvmmrt_add_pktprog(struct netvm_mrt *mrt, struct netvm_program *match,
		       struct netvm_program *action);
int nvmmrt_execute(struct netvm_mrt *rt);
void nvmmrt_fini(struct netvm_mrt *rt, void (*progfree)(void *));

#endif /* __netvm_rt_h */
