#ifndef __netvm_rt_h
#define __netvm_rt_h

#include "netvm.h"
#include <stdio.h>

struct netvm_segdesc {
	uint			len;
	uint			perms;
	struct raw		init;
};

struct netvm_program {
	int			matchonly;
	struct netvm_inst *	inst;
	size_t			ninst;
	struct netvm_segdesc	sdescs[NETVM_MAXMSEGS];
	uint64_t		cpreqs[NETVM_MAXCOPROC];
};

int nvmp_validate(struct netvm_program *prog, struct netvm *vm);
void nvmp_init_mem(struct netvm_program *prog, struct netvm *vm);
int nvmp_exec(struct netvm_program *prog, struct netvm *vm, uint64_t *vmrv);


#define NVMP_RDE_OK       0
#define NVMP_RDE_RUNTHDR  1
#define NVMP_RDE_BADMAGIC 2
#define NVMP_RDE_NOINST   3
#define NVMP_RDE_TOOSMALL 4
#define NVMP_RDE_TOOBIG   5
#define NVMP_RDE_BADNINST 6
#define NVMP_RDE_BADNCPI  7
#define NVMP_RDE_BADNSEG  8
#define NVMP_RDE_BADCPI   9
#define NVMP_RDE_BADSEGN  10
#define NVMP_RDE_BADSEGP  11
#define NVMP_RDE_BADSEGL  12
#define NVMP_RDE_BADSEGI  13
#define NVMP_RDE_OOMEM	  14

int nvmp_read(struct netvm_program *prog, FILE *infile, int *err);
int nvmp_write(struct netvm_program *prog, FILE *outfile);
/* Should only be called for programs read with nfmp_read() */
void nvmp_clear(struct netvm_program *prog);

struct netvm_matchedprog {
	struct netvm_program *	match;
	struct netvm_program *	action;
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
	struct netvm_program *	eprog;
};

void nvmmrt_init(struct netvm_mrt *mrt, uint ssz, uint msz,
		 struct netvm_rt_io *io);
int nvmmrt_set_begin(struct netvm_mrt *mrt, struct netvm_program *prog);
int nvmmrt_set_end(struct netvm_mrt *mrt, struct netvm_program *prog);
int nvmmrt_add_pktprog(struct netvm_mrt *mrt, struct netvm_program *match,
		       struct netvm_program *action);
int nvmmrt_execute(struct netvm_mrt *rt);
void nvmmrt_fini(struct netvm_mrt *rt, void (*progfree)(void *));

#endif /* __netvm_rt_h */
