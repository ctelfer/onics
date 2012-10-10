/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * netvm_prog.c -- A library for manipulating NetVM programs including
 *   storing/retrieving them externally.
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include <cat/pack.h>

#include "netvm_prog.h"
#include "netvm_op_macros.h"

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


void nvmp_init(struct netvm_program *prog)
{
	int i;
	struct netvm_segdesc *sd;

	abort_unless(prog);

	memset(prog, 0, sizeof(*prog));

	/* mostly redundant but explicit */
	prog->inst = NULL;
	prog->ninst = 0;
	for (i = 0; i < NVMP_EP_NUMEP; ++i)
		prog->eps[i] = NVMP_EP_INVALID;
	for (i = 0, sd = prog->sdescs; i < NETVM_MAXMSEGS; ++i, ++sd) {
		sd->perms = 0;
		sd->len = 0;
	}
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;
	prog->inits = NULL;
	prog->ninits = 0;
}


int nvmp_ep_is_set(struct netvm_program *prog, int ep)
{
	abort_unless(prog && ep >= 0 && ep < NVMP_EP_NUMEP);
	return prog->eps[ep] != NVMP_EP_INVALID;
}


int nvmp_validate(struct netvm *vm, struct netvm_program *prog)
{
	uint i;
	int rv = 0;
	struct netvm_segdesc *sd;
	struct netvm_meminit *mi;
	struct netvm_mseg *ms;
	struct netvm_segdesc msave[NETVM_MAXMSEGS];

	abort_unless(vm && prog);

	if (prog->ninst < 1)
		return NETVM_VERR_PROG;

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog->sdescs[i];
		ms = &vm->msegs[i];
		if (((sd->perms & ~NETVM_SEG_PMASK) != 0) ||
		    ((sd->perms & ms->perms) != sd->perms) ||
		    (sd->len > ms->len))
			return NETVM_VERR_PROG;
	}

	if ((prog->ninits > 0) && (prog->inits == NULL))
		return -1;
	for (i = 0; i < prog->ninits; ++i) {
		mi = &prog->inits[i];
		if (mi->segnum >= NETVM_MAXMSEGS)
			return NETVM_VERR_PROG;
		if (vm->msegs[mi->segnum].base == NULL)
			return NETVM_VERR_PROG;
		sd = &prog->sdescs[mi->segnum];
		/* check for overflow */
		if (UINT_MAX - mi->off < mi->val.len)
			return NETVM_VERR_PROG;
		if (mi->off + mi->val.len > sd->len)
			return NETVM_VERR_PROG;
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		if ((prog->cpreqs[i] != NETVM_CPT_NONE) && 
		    (vm->coprocs[i]->type != prog->cpreqs[i]))
			return NETVM_VERR_BADCP;

	netvm_set_code(vm, prog->inst, prog->ninst);
	netvm_set_matchonly(vm, prog->matchonly);
	install_mseg(vm, prog, msave);

	rv = netvm_validate(vm);

	/* Clean up */
	netvm_set_code(vm, NULL, 0);
	restore_mseg(vm, msave);

	return rv;
}


void nvmp_init_mem(struct netvm *vm, struct netvm_program *prog)
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
		if (mi->val.data == NULL)
			memset(ms->base + mi->off, 0, mi->val.len);
		else
			memmove(ms->base + mi->off, mi->val.data, mi->val.len);
	}
}


int nvmp_exec(struct netvm *vm, struct netvm_program *prog, int ep, int maxc,
	      uint64_t *vmrv)
{
	int rv;
	struct netvm_segdesc msave[NETVM_MAXMSEGS];

	abort_unless(prog && vm);
	abort_unless((ep >= 0 && ep < NVMP_EP_NUMEP) ||
		     (ep == NVMP_EXEC_CONTINUE));
	if (ep != NVMP_EXEC_CONTINUE) {
		netvm_set_code(vm, prog->inst, prog->ninst);
		netvm_set_matchonly(vm, prog->matchonly);
		netvm_restart(vm);
		netvm_set_pc(vm, prog->eps[ep]);
	}
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
	ullong cpt;
	ulong segnum, off, len, perms;
	size_t ilen;
	int e = NVMP_RDE_OK;

	abort_unless(prog);
	nvmp_init(prog);

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
		ilen = 0;
		if (!(segnum & NVMP_ZINIT))
			ilen = (len + 3) & ~3;
		segnum &= NVMP_SEGMASK;
		if (segnum >= NETVM_MAXMSEGS) {
			e = NVMP_RDE_MISEG;
			goto err;
		}
		sd = &prog->sdescs[segnum];
		if ((off > sd->len) || (sd->len - off < len)) {
			e = NVMP_RDE_MIOFFLEN;
			goto err;
		}
		if (ilen > 0) {
			if (milen < ilen) {
				e = NVMP_RDE_MITOTLEN;
				goto err;
			}
			if ((mi->val.data = malloc(ilen)) == NULL) {
				e = NVMP_RDE_OOMEM;
				goto err;
			}
			if (fread(mi->val.data, 1, ilen, infile) < ilen) {
				e = NVMP_RDE_TOOSMALL;
				goto err;
			}
			memset(mi->val.data + len, 0, ilen - len);
		} else {
			mi->val.data = NULL;
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
		if (mi->val.data != NULL) {
			ilen = (mi->val.len + 3) & ~(size_t)3;
			if (ULONG_MAX - milen < ilen)
				return -1;
			milen += ilen;
		}
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
		     (ullong)prog->cpreqs[i]);
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
		ulong segnum = mi->segnum;
		/* if the data pointer is NULL, that means initialize with 0s */
		if (mi->val.data == NULL)
			segnum |= NVMP_ZINIT;
		pack(buf, sizeof(buf), "www", segnum, (ulong)mi->off,
		     (ulong)mi->val.len);
		if (fwrite(buf, 1, NVMP_MIHLEN, outfile) < NVMP_MIHLEN)
			return -1;
		/* Nothing to write for zero-initializations */
		if (mi->val.data == NULL)
			continue;
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
			free(prog->inits[i].val.data);
			prog->inits[i].val.data = NULL;
			prog->inits[i].val.len = 0;
		}
		free(prog->inits);
	}

	prog->inits = 0;
	prog->inits = NULL;
}


void nvmp_prret(FILE *f, struct netvm *vm, int rv, uint64_t rc)
{
	abort_unless(f && vm);
	if (rv == 0) {
		fprintf(f, "VM provided no return value\n");
	} else if (rv == 1) {
		fprintf(f, "VM returned value %llu (0x%llx)\n", (ullong)rc,
			(ullong)rc);
	} else if (rv == -1) {
		fprintf(f, "VM returned error @%u: %s\n", vm->pc,
			netvm_estr(vm->status));
	} else if (rv == -2) {
		fprintf(f, "VM quanta expired @%u\n", vm->pc);
	} else {
		fprintf(f, "VM returned unknown error @%u: %s\n", vm->pc,
			netvm_estr(vm->status));
	}
}


void nvmp_prstk(FILE *f, struct netvm *vm)
{
	uint sp;
	sp = vm->sp;
	fprintf(f, "Stack: (SP = %u, BP = %u)\n", sp, vm->bp);
	while (sp > 0) {
		--sp;
		fprintf(f, "\t%4u: %llu (0x%llx)\n", sp,
		        (ullong)vm->stack[sp],
		        (ullong)vm->stack[sp]);
	}
}


static int sendpkt(struct netvm *vm, uint64_t pn, FILE *f, FILE *dout,
		   int flags)
{
	int debug = flags & NVMP_RUN_DEBUG;
	struct pktbuf *p;
	int esave;

	if (pn >= NETVM_MAXPKTS) {
		if (debug)
			fprintf(dout, "Packet number %llu is not valid.\n",
				(ullong)pn);
		return -1;
	}

	p = netvm_clr_pkt(vm, pn, 1);

	if (p == NULL) {
		if (debug)
			fprintf(dout, "Packet %llu does not exist.\n",
				(ullong)pn);
		return -1;
	}

	if (pkb_pack(p) < 0) {
		if (debug) {
			esave = errno;
			fprintf(dout, "Error packet packet for writing\n");
			errno = esave;
		}
		return -1;
	}

	if (pkb_file_write(p, f) < 0) {
		if (debug) {
			esave = errno;
			fprintf(dout, "Error writing out packet\n");
			errno = esave;
		}
		return -1;
	}

	if (debug)
		fprintf(dout, "Sent packet\n");

	return 0;
}


static int flushpkts(struct netvm *vm, int send, FILE *f, FILE *dout, int flags)
{
	int debug = flags & NVMP_RUN_DEBUG;
	int i;
	struct pktbuf *p;

	for (i = 0; i < NETVM_MAXPKTS; ++i) {
		if (netvm_pkt_isvalid(vm, i)) {
			if (send) {
				if (sendpkt(vm, i, f, dout, flags) < 0)
					return -1;
			} else {
				if (debug)
					fprintf(dout, "Dropping packet %d\n",
						i);

				p = netvm_clr_pkt(vm, i, 1);
				pkb_free(p);
			}
		}
	}

	return 0;
}


static const char *epstr[] = {
	"START",
	"PACKET",
	"END",
};

static const char *nvmp_epstr(int epi)
{
	if (epi < 0 || epi >= NVMP_EP_NUMEP)
		return "UNKNOWN";
	else
		return epstr[epi];
}


static int _nvmp_run(struct netvm *vm, struct netvm_program *prog, int epi,
		     FILE *pout, FILE *dout, int flags)
{
	int rv;
	int status;
	int pass;
	int debug = flags & NVMP_RUN_DEBUG;
	int ignerr = flags & NVMP_RUN_IGNORE_ERR;
	int prstk = flags & NVMP_RUN_PRSTK;
	uint64_t tos = 0;

	if (prog->eps[epi] == NVMP_EP_INVALID) {
		if (debug)
			fprintf(dout, "No %s entry point\n", nvmp_epstr(epi));
		return 0;
	}

	if (debug)
		fprintf(dout, "Program has a valid %s entry point\n",
			nvmp_epstr(epi));

restart:
	if (flags & NVMP_RUN_SINGLE_STEP) {

		if (debug) {
			fprintf(dout, "Single stepping netvm program\n");
			fprintf(dout, "Executing instruction %u\n",
				(epi == NVMP_EXEC_CONTINUE ? 
				 vm->pc : prog->eps[epi]));
		}

		rv = nvmp_exec(vm, prog, epi, 1, &tos);

		if (prstk)
			nvmp_prstk(dout, vm);

		while (rv == -2) {

			if (debug)
				fprintf(dout, "Executing instruction %u\n",
					vm->pc);

			rv = nvmp_exec(vm, prog, NVMP_EXEC_CONTINUE, 1, &tos);

			if (prstk)
				nvmp_prstk(dout, vm);
		}
	} else {
		if (debug)
			fprintf(dout, "Running netvm program to completion\n");

		rv = nvmp_exec(vm, prog, epi, -1, &tos);
	}

	if (debug)
		nvmp_prret(dout, vm, rv, tos);

	if (prstk)
		nvmp_prstk(dout, vm);

	status = vm->status;
	if (rv < 0) {
		if (ignerr)
			status = NVMP_STATUS_DROPALL;
		else
			return -1;
	}

	switch (status) {
	case NVMP_STATUS_DONE:
		if (rv == 0)
			tos = 0;

		if (debug)
			fprintf(dout, "Halt status DONE: top of stack %llu\n",
				(ullong)tos);

		if (flushpkts(vm, tos != 0, pout, dout, flags) < 0)
			return (ignerr ? 0 : -1);
		return tos != 0;

	case NVMP_STATUS_SENDALL:
		if (debug)
			fprintf(dout, "Halt status SENDALL\n");

		if (flushpkts(vm, 1, pout, dout, flags) < 0)
			return (ignerr ? 0 : -1);
		return 1;

	case NVMP_STATUS_DROPALL:
		if (debug)
			fprintf(dout, "Halt status DROPALL\n");

		if (flushpkts(vm, 0, pout, dout, flags) < 0)
			return (ignerr ? 0 : -1);
		return 0;

	case NVMP_STATUS_SEND:
		/* make sure there is a top of stack and send one packet */
		if (rv == 0) {
			if (debug)
				fprintf(dout, 
					"Halt status SEND with no "
					"packet number on the stack\n");
			return -1;
		}

		if (debug)
			fprintf(dout, "Halt condition was SEND of packet %d\n",
			        (int)tos);

		S_POP_NOCK(vm, tos);
		rv = sendpkt(vm, tos, pout, dout, flags);
		if (rv < 0 && !ignerr) {
			return -1;
		} else {
			++vm->pc;
			epi = NVMP_EXEC_CONTINUE;
			if (debug)
				fprintf(dout, "Restarting at %u\n", vm->pc);
			goto restart;
		}

	case NVMP_STATUS_EXIT:
		if (rv == 0)
			tos = 0;

		if (debug)
			fprintf(dout, "Halt status EXIT with code %d\n", (int)tos);

		exit(tos);
	}
}


int nvmp_run_all(struct netvm *vm, struct netvm_program *prog, FILE *pin,
		 FILE *pout, FILE *dout, int flags)
{
	ulong npkt = 0;
	ulong npass = 0;
	int ignerr = flags & NVMP_RUN_IGNORE_ERR;
	int debug = flags & NVMP_RUN_DEBUG;
	int rv;
	int esave;
	uint64_t tos;
	struct pktbuf *p;

	if (debug && dout == NULL) {
		errno = EINVAL;
		return -1;
	}

	nvmp_init_mem(vm, prog);

	rv = _nvmp_run(vm, prog, NVMP_EP_START, pout, dout, flags);
	if (rv < 0)
		return -1;

	if (prog->eps[NVMP_EP_PACKET] != NVMP_EP_INVALID) {

		if (debug)
			fprintf(dout, "Processing packets in '%s' mode.\n",
				(vm->matchonly ? "match only" : "standard"));

		while (pkb_file_read(&p, pin) > 0) {

			if (pkb_parse(p) < 0) {
				if (dout != NULL) {
					esave = errno;
					fprintf(dout,
						"Error parsing packet %lu\n",
						npkt);
					errno = esave;
				}
				return -1;
			}
			++npkt;

			if (debug)
				fprintf(dout, "Read packet %lu\n", npkt);

			netvm_load_pkt(vm, p, 0);
			rv = _nvmp_run(vm, prog, NVMP_EP_PACKET, pout, dout,
				       flags);
			if (rv < 0)
				return -1;

			if (rv == 1) {
				if (debug)
					fprintf(dout, "Packet %lu passed\n",
						npkt);
				++npass;
			}

		}

		if (debug)
			fprintf(dout, "%lu packets processed and %lu passed\n",
				npkt, npass);
		
	} else {

		if (debug)
			fprintf(dout,
				"No %s entry point: no packet read/write\n",
				nvmp_epstr(NVMP_EP_PACKET));

	}


	rv = _nvmp_run(vm, prog, NVMP_EP_END, pout, dout, flags);
	if (rv < 0)
		return -1;

	return 0;
}

