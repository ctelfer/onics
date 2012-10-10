/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * netvm_prog.h -- API for NetVM programs.
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

/*
 * This file prototypes the interface for a program format for netvm programs.
 * The programs described in this file format follow an AWK-style format
 * where there are code snippits to run at the beginning and end of processing
 * and then there are rule snippits to run on each packet in the stream.
 * NetVM itself is not tied to this mode of operation.  So, perhaps this file
 * should be renamed to be a bit more clear.  This file format is the one
 * that the NetVM assembler (nvmas) currently targets and th NetVM packet 
 * filter (nvmpf) currently runs.  
 *
 * This API provides the following:
 *  - An external file format for NetVM programs
 *  - Routines for loading, initializing and running programs from the format
 *  - Conventions for moving packets through the programs in this format
 *  - Debugging facilities for inspecting NetVM programs and their runtime
 *    state.
 */
#ifndef __netvm_prog_h
#define __netvm_prog_h

#include "netvm.h"
#include <stdio.h>

/* 
 * status conditions to be handled by the runtime environment 
 *
 *  - DONE expects a single boolean value on the stack.  It
 *    indicates that the program should halt the current processing
 *    (BEGIN block, END block or rules for this packet).  If the
 *    boolean stack value is 'true' all remaining packets should be
 *    sent.  Otherwise they should be discarded.
 *
 *  - SENDALL expects nothing on the stack but is equivalent to DONE
 *    with a value of 1 on the top of the stack.
 *
 *  - DROPALL expects nothing on the stack but is equivalent to DONE
 *    with a value of 0 on the top of the stack.
 *
 *  - SEND expects a packet number on the stack.  It indicates for
 *    the runtime to transmit the packet and then re-enter execution.
 * 
 *  - EXIT expects a value on the stack.  It indicates that all
 *    processing should immediately cease and the process should
 *    should exit with the value on the stack modulo 256.
 */ 
#define NVMP_STATUS_DONE   	NETVM_STATUS_STOPPED
#define NVMP_STATUS_SENDALL	NETVM_STATUS_RTDEF0
#define NVMP_STATUS_DROPALL	NETVM_STATUS_RTDEF1
#define NVMP_STATUS_SEND	NETVM_STATUS_RTDEF2
#define NVMP_STATUS_EXIT 	NETVM_STATUS_RTDEF3

struct netvm_segdesc {
	uint			len;
	uint			perms;
};


struct netvm_meminit {
	uint 			segnum;
	uint			off;
	struct raw		val;
};


#define NVMP_EP_INVALID		(uint)-1
#define NVMP_EXEC_CONTINUE	NVMP_EP_INVALID
/* Entry points in the netvm program */
enum {
	NVMP_EP_START,
	NVMP_EP_PACKET,
	NVMP_EP_END,
	NVMP_EP_NUMEP,
};
struct netvm_program {
	int			matchonly;		
	struct netvm_inst *	inst;
	uint			ninst;
	uint			eps[NVMP_EP_NUMEP];
	struct netvm_segdesc	sdescs[NETVM_MAXMSEGS];
	uint64_t		cpreqs[NETVM_MAXCOPROC];
	struct netvm_meminit	*inits;
	uint			ninits;
};


/* clear/initialize a netvm program for population.  */
/* not needed for nvmp_read(). */
void nvmp_init(struct netvm_program *prog);

/* Determine whether a program has a particular type of entry point defined */
int nvmp_ep_is_set(struct netvm_program *prog, int ep);

/* returns the same error codes as netvm_validate */
int nvmp_validate(struct netvm *vm, struct netvm_program *prog);

/* Assumes that the VM already has sufficient memory for the program. */
/* This is checked in nvmp_validate(). */
void nvmp_init_mem(struct netvm *vm, struct netvm_program *prog);

/* Returns the same error codes as netvm_run.  Use netvm_run() to continue */
/* execution if the program runs out of cycles. */
int nvmp_exec(struct netvm *vm, struct netvm_program *prog, int ep, int maxcycles,
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
 *  -- 7 -- initialization entry point
 *  -- 8 -- packet entry point
 *  -- 9 -- finalization entry point
 *  -- <# instr> * 8 bytes --  instructions
 *  -- <# cpreqs> * 12 bytes --  coprocessor requirements
 *  -- <# segs> * 12 bytes -- segment sections
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
 *     - or -
 *    segnum|(1<<31)[4] off[4] len[4]
 *     *This one is to initialize with 0s*
 */

#define NVMP_MAGIC	0x4E564D50
#define NVMP_V1		1
#define NVMP_HLEN	40
#define NVMP_INSTLEN	8
#define NVMP_NUMEPS	3
#define NVMP_CPLEN	12
#define NVMP_SEGPLEN	12
#define NVMP_MIHLEN	12
#define NVMP_ZINIT	0x80000000
#define NVMP_SEGMASK	0x7FFFFFFF


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

/* Pretty-print the return value of the virtual machine */
void nvmp_prret(FILE *f, struct netvm *vm, int rv, uint64_t tos);

/* Dump the stack of the virtual machine */
void nvmp_prstk(FILE *f, struct netvm *vm);



enum {
	NVMP_RUN_SINGLE_STEP = 1,	/* Run the prog by single-stepping it */
	NVMP_RUN_IGNORE_ERR = 2,	/* Ignore netvm program errors */
	NVMP_RUN_DEBUG = 4,		/* Debug print info about execution */
	NVMP_RUN_PRSTK = 8,		/* Print the VM stack during and/or */
					/* after the execution run. */
};


/* Run a complete netvm program given a VM, packet source, packet sink, */
/* debug output (if NVMP_RUN_DEBUG or NVMP_RUN_PRSTK are set) and flags. */
int nvmp_run_all(struct netvm *vm, struct netvm_program *prog,
	         FILE *pin, FILE *pout, FILE *dout, int flags);

#endif /* __netvm_prog_h */
