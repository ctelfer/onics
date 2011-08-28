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
	uint			ep;			/* entry point */
	struct netvm_segdesc	sdescs[NETVM_MAXMSEGS];
	uint64_t		cpreqs[NETVM_MAXCOPROC];
	struct netvm_meminit	*inits;
	uint			ninits;
};


/* returns the same error codes as netvm_validate */
int nvmp_validate(struct netvm_program *prog, struct netvm *vm);

/* Assumes that the VM already has sufficient memory for the program. */
/* This is checked in nvmp_validate(). */
void nvmp_init_mem(struct netvm_program *prog, struct netvm *vm);

/* Returns the same error codes as netvm_run */
int nvmp_exec(struct netvm_program *prog, struct netvm *vm, int maxcycles,
	      uint64_t *vmrv);

/*
 * NetVM Program file format: 
 *
 * All multibyte fields are stored big endian.
 * For simplicity, each base field is a 32-bit unsigned integer.
 *  -- 0 -- Magic (0x4E564D50 "NVMP")
 *  -- 1 -- 1B: version, 1B matchonly, 2B reserved
 *  -- 2 -- number of instructions
 *  -- 3 -- number of co-processor requirements
 *  -- 4 -- number of segment sections
 *  -- 5 -- number of mem inits
 *  -- 6 -- mem initialization length 
 *  -- 7 -- reserved
 *  -- <# instr> * 8 bytes --  instructions
 *  -- <# cpreqs> * 12 bytes --  coprocessor requirements
 *  -- <# segs> -- segment sections
 *  -- <# mem inits> -- memory initializations
 *
 *  Instruction format:
 *    opcode[1] x[1] y[1] z[1] w[4]
 *
 *  Co Processor requirement format:
 *    cpi[4] cpt[8]
 *
 *  Segment format:
 *    segnum[4] len[4] perms[4]
 *
 *  Memory initialization format:
 *    segnum[4] off[4] len[4] <data padded to 4 byte multiples>
 */

#define NVMP_MAGIC	0x4E564D50
#define NVMP_V1		1
#define NVMP_HLEN	32
#define NVMP_INSTLEN	8
#define NVMP_CPLEN	12
#define NVMP_SEGPLEN	12
#define NVMP_MIHLEN	12


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
#define NVMP_RDE_MITOTLEN 13
#define NVMP_RDE_MILEN    14
#define NVMP_RDE_MISEG    15 
#define NVMP_RDE_MIOFFLEN 17 
#define NVMP_RDE_OOMEM	  18
#define NVMP_RDE_BADEP    19

/* TODO: modify file format and nvmp_read() call to allow patching */
/* of program, especially for coprocessor layout and initialization. */
int nvmp_read(struct netvm_program *prog, FILE *infile, int *err);
int nvmp_write(struct netvm_program *prog, FILE *outfile);

/* Should only be called for programs read with nfmp_read() */
void nvmp_clear(struct netvm_program *prog);

#endif /* __netvm_prog_h */
