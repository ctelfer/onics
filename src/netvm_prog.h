#ifndef __netvm_prog_h
#define __netvm_prog_h

#include "netvm.h"
#include <stdio.h>

struct netvm_segdesc {
	uint			len;
	uint			perms;
};


struct netvm_meminit {
	uint 			segnum;
	uint			off;
	struct raw		val;
};


struct netvm_program {
	int			matchonly;
	struct netvm_inst *	inst;
	uint			ninst;
	struct netvm_segdesc	sdescs[NETVM_MAXMSEGS];
	uint64_t		cpreqs[NETVM_MAXCOPROC];
	struct netvm_meminit	*inits;
	uint			ninits;

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
#define NVMP_RDE_OOMEM	  13

int nvmp_read(struct netvm_program *prog, FILE *infile, int *err);
int nvmp_write(struct netvm_program *prog, FILE *outfile);
/* Should only be called for programs read with nfmp_read() */
void nvmp_clear(struct netvm_program *prog);

#endif /* __netvm_prog_h */
