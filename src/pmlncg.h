/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * pmlncg.h -- API for PML code generation for the NetVM platform.
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
#ifndef __pmlncg_h
#define __pmlncg_h

#include "ns.h"
#include "prid.h"
#include "pmltree.h"
#include "netvm.h"
#include "netvm_prog.h"
#include "protoparse.h"
#include "util.h"


struct pml_ibuf {
	struct netvm_inst *	inst;
	uint			ninst;		/* # instructions in use */
	uint			size;		/* in instructions */
	uint			addr;
};


void pib_init(struct pml_ibuf *b);
void pib_clear(struct pml_ibuf *b);
int  pib_add(struct pml_ibuf *b, struct netvm_inst *i);


enum {
	PMLCG_MI_RO,
	PMLCG_MI_IRW,
	PMLCG_MI_URW,
	PMLCG_MI_NUM
};


struct callsite {
	struct pml_function *	func;
	uint			iaddr;
};


#define PMLNCG_MAXERR		256


struct pmlncg {

	struct pml_ast *	ast;		/* AST we are building from */
	struct netvm_program *	prog;		/* program we are generating */
	struct pml_ibuf		ibuf;		/* current instruction buf */

	struct pml_function *	curfunc;
	struct pml_while *	curloop;

	/* resolve these after function geration */
	struct dynbuf		calls;

	/* resolve these after codegen for loops */
	struct dynbuf		breaks; 	/* unresolved 'break's */
	struct dynbuf		continues;	/* unresolved 'continue's */

	/* resolve these after codegen for rules */
	struct dynbuf		nextrules;	/* unresolved 'nextrule's */

	char 			err[PMLNCG_MAXERR];	/* error buffer */
};

/*
 * There are some standardized things about PML programs compiled to netvm:
 *  + There are 2 memory segments: read-only (PML_SEG_ROMEM) and read-write
 *    PML_SEG_RWMEM.
 *
 *  + There are 3 memory initializations:  one for read-only mem, one for
 *    explicitly initialized read-write mem, and one for read-write mem
 *    with no initialization (initialized to 0)
 *
 *  + PML requires all 4 of the standard coprocessors in their default
 *    coprocessor indices:  XPKT, OUTPORT, PKTQ, REX.  Future work may
 *    make these discoverable at runtime.
 *
 *  + The first few instructions in the code store will be "mini
 *    subroutines" (you jump to them rather than call them) for the
 *    actions of dropping a packet or going to the next packet.
 *
 *  + Regular expression initialization must be coded in the 'begin'
 *    entry point before the actual BEGIN code in PML.
 */

/*
 * Compile a PML AST to a netvm program that can be stored or run.
 * if 'copy' is set then the operation is non-destructive and the
 * memory initializations get copied from the ast to the program.
 * otherwise, the ast gets cleared and some of the memory originally
 * used in the ast becomes owned by the program.
 */
int pml_to_nvmp(struct pml_ast *ast, struct netvm_program *prog, int copy,
		char ebuf[PMLNCG_MAXERR]);


/* Clear out the auxilliary data for a netvm program that was initialized */
/* but from an AST without AST data copy. */
int pml_nvmp_clear_nocopy(struct netvm_program *prog);

#endif /* __pmlncg_h */
