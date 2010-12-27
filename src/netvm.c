#include "config.h"
#include "netvm.h"
#include <string.h>
#include <stdlib.h>
#include <cat/emit_format.h>
#include <cat/bitops.h>
#include <cat/pack.h>
#include "util.h"

/* 
 * TODO:  If the host processor doesn't support unaligned data access (e.g. 
 * xscale),then the load and store operations need to be revamped to use 
 * memmove/memcpy to load and store data values.  This can wait for later.
 */

#include "netvm_op_macros.h"

#define MAXINST         0x7ffffffe
#define PPT_TO_LIDX(ppt) ((ppt) & 0x3)


int netvm_valid_width(int width)
{
	return ((width & 0x7F) > 0) && 
	       ((width & 0x7f) <= 8) && 
	       ((width & ~0xFF) == 0);
}


/* Pull a packet descriptor from the stack or from the current instruction */
void netvm_get_pd(struct netvm *vm, struct netvm_prp_desc *pd, int onstack)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t val;
	if (onstack) {
		S_POP(vm, val);
		pd->ptype = (val >> NETVM_PD_PPT_OFF) & NETVM_PD_PPT_MASK;
		pd->pktnum = (val >> NETVM_PD_PKT_OFF) & NETVM_PD_PKT_MASK;
		pd->pktnum &= ~NETVM_SEG_ISPKT;
		pd->idx = (val >> NETVM_PD_IDX_OFF) & NETVM_PD_IDX_MASK;
		pd->field = (val >> NETVM_PD_FLD_OFF) & NETVM_PD_FLD_MASK;
		val = (val >> NETVM_PD_OFF_OFF) & NETVM_PD_OFF_MASK;
		pd->offset = sign_extend(val, 32);
	} else {
		pd->pktnum = inst->y & ~NETVM_SEG_ISPKT;
		pd->idx = (inst->z >> 4) & 0xF;
		pd->field = (inst->z & 0xF);
		pd->ptype = (inst->w >> 16) & 0xFFFF;
		pd->offset = inst->w & 0xFFFF;
	}
}


/* 
 * find header based on packet number, header type, and index.  So (3,8,1) 
 * means find the 2nd (0-based counting) TCP (PPT_TCP == 8) header in the 4th
 * packet.
 */
struct prparse *netvm_find_header(struct netvm *vm, struct netvm_prp_desc *pd,
				  int onstack)
{
	struct pktbuf *pkb;
	struct prparse *prp;
	int n = 0;

	netvm_get_pd(vm, pd, onstack);
	if (vm->error)
		return NULL;

	if (pd->pktnum >= NETVM_MAXPKTS)
		VMERRRET(vm, NETVM_ERR_PKTNUM, NULL);

	if (!(pkb = vm->packets[pd->pktnum]))
		VMERRRET(vm, NETVM_ERR_NOPKT, NULL);

	if (PPT_IS_PCLASS(pd->ptype)) {
		uint lidx = PPT_TO_LIDX(pd->ptype);
		return pkb->layers[lidx];
	}

	prp = &pkb->prp;
	do {
		if ((pd->ptype == PPT_ANY) || (pd->ptype == prp->type)) {
			if (n == pd->idx)
				return prp;
			++n;
		}
		prp = prp_next(prp);
	} while (!prp_list_end(prp));
	return NULL;
}


void netvm_get_prp_ptr(struct netvm *vm, struct netvm_inst *inst, int onstack,
		       int width, byte_t **p)
{
	struct netvm_prp_desc pd0;
	struct prparse *prp;
	uint oidx;
	uint64_t off;

	if (onstack && inst->z != 0) {
		int pktnum;
		struct pktbuf *pkb;

		/* pd0.pktnum = inst->y & ~NETVM_SEG_ISPKT; */
		/* pd0.idx = 0; pd0.ptype = PPT_NONE; */
		/* pd0.field = NETVM_PRP_SOFF; */
		S_POP(vm, pd0.offset);

		pktnum = inst->y & ~NETVM_SEG_ISPKT;
		FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
		FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
		prp = &pkb->prp;
		oidx = PRP_OI_SOFF;
	} else {
		prp = netvm_find_header(vm, &pd0, onstack);
		if (vm->error)
			return;
		FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
		FATAL(vm, NETVM_ERR_PRPFLD, !NETVM_ISPRPOFF(pd0.field));
		oidx = pd0.field - NETVM_PRP_OFF_BASE;
		if ((pd0.field < NETVM_PRP_OFF_BASE) || (oidx >= prp->noff))
			VMERR(vm, NETVM_ERR_PRPFLD);
		FATAL(vm, NETVM_ERR_PKTADDR, (prp->offs[oidx] == PRP_OFF_INVALID));
	}

	FATAL(vm, NETVM_ERR_IOVFL, (pd0.offset + width < pd0.offset));
	off = prp->offs[oidx] + pd0.offset;
	FATAL(vm, NETVM_ERR_PKTADDR, off < prp_soff(prp));
	FATAL(vm, NETVM_ERR_PKTADDR, off + width < off);
	FATAL(vm, NETVM_ERR_PKTADDR, off + width > prp_eoff(prp));

	abort_unless(p);
	*p = prp->data + off;
}


static void ni_unimplemented(struct netvm *vm)
{
	vm->error = NETVM_ERR_UNIMPL;
}


static void ni_nop(struct netvm *vm)
{
	(void)ni_unimplemented;
}


static void ni_pop(struct netvm *vm)
{
	uint64_t v;
	S_POP(vm, v);
}


static void ni_popbp(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	FATAL(vm, NETVM_ERR_STKOVFL, !S_HAS(vm, inst->w));
	vm->sp = vm->bp + inst->w;
}


static void ni_push(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	S_PUSH(vm, (uint64_t)inst->w);
}


static void ni_pushhi(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	S_PUSH(vm, (uint64_t)inst->w << 32);
}


static void ni_zpush(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong i;

	FATAL(vm, NETVM_ERR_STKOVFL, S_AVAIL(vm) < inst->w);

	for (i = 0; i < inst->w; ++i)
	    vm->stack[vm->sp + i] = 0;

	vm->sp += inst->w;
}


/* TODO: recheck boundaries for DUPs and SWAP */
static void ni_dup(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t val;

	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, inst->w + 1));
	val = S_GET(vm, inst->w);
	S_PUSH(vm, val);
}


static void ni_swap(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t tmp = (inst->x > inst->w) ? inst->x : inst->w;
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, tmp + 1));
	tmp = S_GET(vm, inst->x);
	S_SET(vm, inst->x, S_GET(vm, inst->w));
	S_SET(vm, inst->w, tmp);
}


static void ni_ldbp(struct netvm *vm)
{
	uint64_t pos;
	S_POP(vm, pos);
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, pos+1));
	S_PUSH_NOCK(vm, vm->stack[vm->bp + pos]);
}


static void ni_ldbpi(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, inst->w+1));
	S_PUSH(vm, vm->stack[vm->bp + inst->w]);
}


static void ni_stbp(struct netvm *vm)
{
	uint64_t pos, val;
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, 2));
	S_POP_NOCK(vm, pos);
	S_POP_NOCK(vm, val);
	FATAL(vm, NETVM_ERR_STKOVFL, !S_HAS(vm, pos+1));
	vm->stack[vm->bp + pos] = val;
}


static void ni_stbpi(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t val;
	S_POP(vm, val);
	FATAL(vm, NETVM_ERR_STKOVFL, !S_HAS(vm, inst->w+1));
	vm->stack[vm->bp + inst->w + 1] = val;
}


static void ni_pfe(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct prparse *prp;
	uint64_t val = 0;

	prp = netvm_find_header(vm, &pd0, inst->op == NETVM_OC_PFE);
	if (vm->error) {
		if (vm->error == NETVM_ERR_NOPKT) {
			/* unlike other operations that use netvm_find_header, */
			/* pfe(i) do not assume the packet is there.  If */
			/* it is not, we just push 0.  */
			vm->error = 0;
			S_PUSH(vm, 0);
		}
		return;
	}

	if (prp) {
		if (pd0.field < NETVM_PRP_OFF_BASE) {
			val = 1;
		} else {
			uint field = pd0.field - NETVM_PRP_OFF_BASE;
			val = (field < prp->noff) &&
			      (prp->offs[field] != PRP_OFF_INVALID);
		}
	}

	S_PUSH(vm, val);
}


static void ni_ldpf(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct prparse *prp;
	uint oidx;
	long off;
	uint64_t vmoff;

	prp = netvm_find_header(vm, &pd0, (inst->op == NETVM_OC_LDPF));
	if (vm->error)
		return;

	if (!prp) {
		S_PUSH(vm, NETVM_PF_INVALID);
		return;
	}

	switch (pd0.field) {
	case NETVM_PRP_HLEN:
		S_PUSH(vm, prp_hlen(prp));
		break;
	case NETVM_PRP_PLEN:
		S_PUSH(vm, prp_plen(prp));
		break;
	case NETVM_PRP_TLEN:
		S_PUSH(vm, prp_tlen(prp));
		break;
	case NETVM_PRP_LEN:
		S_PUSH(vm, prp_totlen(prp));
		break;
	case NETVM_PRP_ERR:
		S_PUSH(vm, prp->error);
		break;
	case NETVM_PRP_TYPE:
		S_PUSH(vm, prp->type);
		break;
	default:
		abort_unless(pd0.field >= NETVM_PRP_OFF_BASE);
		oidx = pd0.field - NETVM_PRP_OFF_BASE;
		if (oidx >= prp->noff) {
			VMERR(vm, NETVM_ERR_PRPFLD);
		}
		off = prp->offs[oidx];
		if (off != PRP_OFF_INVALID)
			vmoff = off + pd0.offset;
		else
			vmoff = NETVM_PF_INVALID;
		S_PUSH(vm, vmoff);
	}
}


void netvm_p2stk(struct netvm *vm, byte_t *p, int width)
{
	uint64_t val;

	val = 0;
	switch (width & 0x7F) {
	case 8: val |= (uint64_t)*p++ << 56;
	case 7: val |= (uint64_t)*p++ << 48;
	case 6: val |= (uint64_t)*p++ << 40;
	case 5: val |= (uint64_t)*p++ << 32;
	case 4: val |= (uint64_t)*p++ << 24;
	case 3: val |= (uint64_t)*p++ << 16;
	case 2: val |= (uint64_t)*p++ << 8;
	case 1: val |= (uint64_t)*p;
		break;
	default:
		abort_unless(0);	/* should be checked at validation */
		VMERR(vm, NETVM_ERR_WIDTH);
	}

	if ((width & 0x80) != 0)
		val = sign_extend(val, ((width & 0x7F) * 8));

	S_PUSH(vm, val);
}


void netvm_get_mem_ptr(struct netvm *vm, uint8_t seg, uint64_t addr, int iswr, 
		       uint64_t len, byte_t **p)
{
	FATAL(vm, NETVM_ERR_NOMEM, !vm->mem || !vm->memsz);
	FATAL(vm, NETVM_ERR_MEMADDR, seg > NETVM_SEG_ROMEM);
	abort_unless(vm->rosegoff <= vm->memsz);
	abort_unless(vm->memsz >= 8);
	if (seg == NETVM_SEG_RWMEM) {
		FATAL(vm, NETVM_ERR_MEMADDR, addr > vm->memsz);
		FATAL(vm, NETVM_ERR_MEMADDR, len > vm->memsz - addr);
		*p = vm->mem + addr;
	} else {
		uint seglen;
		FATAL(vm, NETVM_ERR_MRDONLY, iswr);
		seglen = vm->memsz - vm->rosegoff;
		FATAL(vm, NETVM_ERR_MEMADDR, addr > seglen);
		FATAL(vm, NETVM_ERR_MEMADDR, len > seglen - addr);
		*p = vm->mem + vm->rosegoff + addr;
	}
}


void netvm_get_pkt_ptr(struct netvm *vm, uint8_t pkt, uint64_t addr, int iswr, 
		       uint64_t len, byte_t **p)
{
	struct pktbuf *pkb;
	struct prparse *prp;
	pkt &= ~NETVM_SEG_ISPKT;
	FATAL(vm, NETVM_ERR_PKTNUM, pkt > NETVM_MAXPKTS);
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pkt]));
	prp = &pkb->prp;
	FATAL(vm, NETVM_ERR_PKTADDR, addr < prp_poff(prp));
	FATAL(vm, NETVM_ERR_PKTADDR, addr > prp_toff(prp));
	FATAL(vm, NETVM_ERR_PKTADDR, len > prp_toff(prp) - addr);
	*p = prp->data + addr;
}


void netvm_get_seg_ptr(struct netvm *vm, uint8_t seg, uint64_t addr, int iswr, 
		       uint64_t len, byte_t **p)
{
	if ((seg & NETVM_SEG_ISPKT) == 0) {
		netvm_get_mem_ptr(vm, seg, addr, iswr, len, p);
	} else {
		netvm_get_pkt_ptr(vm, seg, addr, iswr, len, p);
	}
}


static void ni_ld(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	register uint64_t addr;
	int width;
	byte_t *p;

	width = inst->x;

	if ((inst->y & NETVM_SEG_ISPKT) == 0) {
		/* in a memory region */
		if (inst->op == NETVM_OC_LD) {
			S_POP(vm, addr);
		} else {
			addr = inst->w;
		}
		netvm_get_mem_ptr(vm, inst->y, addr, 0, width & 0x7F, &p);
	} else {
		/* in a packet */
		netvm_get_prp_ptr(vm, inst, (inst->op == NETVM_OC_LD), width,
				  &p);
	}

	if (!vm->error)
		netvm_p2stk(vm, p, width);
}


static void ni_cmp(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t a1, a2, len, val;
	byte_t *p1, *p2;

	S_POP(vm, len);
	S_POP(vm, a1);
	S_POP(vm, a2);

	FATAL(vm, NETVM_ERR_IOVFL, (a1 + len < len) || (a2 + len < len));
	netvm_get_seg_ptr(vm, inst->x, a1, 0, len, &p1);
	if (vm->error)
		return;
	netvm_get_seg_ptr(vm, inst->y, a2, 0, len, &p2);
	if (vm->error)
		return;

	val = memcmp(p1, p2, len);

	/* We've already popped 3 values from the stack */
	S_PUSH_NOCK(vm, val);
}


static void ni_pcmp(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t a1, a2, len, nbytes, val;
	byte_t *p1, *p2;

	S_POP(vm, len);
	S_POP(vm, a1);
	S_POP(vm, a2);

	FATAL(vm, NETVM_ERR_IOVFL, len + 7 < len);
	nbytes = (len + 7) >> 3;

	FATAL(vm, NETVM_ERR_IOVFL,
	      (a1 + nbytes < nbytes) || (a2 + nbytes < nbytes));

	netvm_get_seg_ptr(vm, inst->x, a1, 0, len, &p1);
	if (vm->error)
		return;
	netvm_get_seg_ptr(vm, inst->y, a2, 0, len, &p2);
	if (vm->error)
		return;

	val = 0;
	while (len > 8) {
		if (*p1 != *p2) {
			val = (*p1 < *p2) ? (0 - (uint64_t) 1) : 1;
			S_PUSH(vm, val);
			break;
		}
		++p1;
		++p2;
		len -= 8;
	}
	if ((len > 0) && !val) {
		byte_t b1 = *p1 & -(1 << (8 - len));
		byte_t b2 = *p2 & -(1 << (8 - len));
		if (b1 != b2)
			val = (b1 < b2) ? (0 - (uint64_t) 1) : 1;
	}

	/* We've already popped 3 values from the stack */
	S_PUSH_NOCK(vm, val);
}


static void ni_mskcmp(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t a1, a2, am, len;
	byte_t *p1, *p2, *pm;

	S_POP(vm, len);
	S_POP(vm, am);
	S_POP(vm, a2);
	S_POP(vm, a1);

	FATAL(vm, NETVM_ERR_IOVFL, (a1 + len < len) || (a2 + len < len) || 
	      (am + len < len));

	netvm_get_seg_ptr(vm, inst->x, a1, 0, len, &p1);
	if (vm->error)
		return;
	netvm_get_seg_ptr(vm, inst->y, a2, 0, len, &p2);
	if (vm->error)
		return;
	netvm_get_seg_ptr(vm, inst->z, am, 0, len, &pm);
	if (vm->error)
		return;

	while (len > 0) {
		if ((*p1++ & *pm) != (*p2++ & *pm)) {
			S_PUSH_NOCK(vm, 0);
			return;
		}
		++pm;
		--len;
	}

	/* We've already popped 4 values from the stack. */
	S_PUSH_NOCK(vm, 1);
}


static void ni_unop(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t val;

	S_POP(vm, val);

	switch(inst->op) {
	case NETVM_OC_NOT:
		val = !val;
		break;
	case NETVM_OC_INVERT:
		val = ~val;
		break;
	case NETVM_OC_TOBOOL:
		val = val != 0;
		break;
	case NETVM_OC_POPL:	/* fall through */
	case NETVM_OC_NLZ:
		FATAL(vm, NETVM_ERR_WIDTH, inst->x > 8);
		if (inst->x < 8)
			val &= (1 << (inst->x * 8)) - 1;
		if (inst->op == NETVM_OC_POPL) {
			val = pop_64(val);
		} else {
			val = nlz_64(val) - (64 - inst->x * 8);
		}
		break;
	case NETVM_OC_SIGNX:
		switch(inst->x) {
		FATAL(vm, NETVM_ERR_WIDTH, inst->x > 8);
		val = val | -(val & (1 << (inst->x * 8 - 1)));
		}
	default:
		val = 0;
		abort_unless(0);
	}

	/* All unary operations pop their operands from stack. */
	/* So no need to check for stack bounds. */
	S_PUSH_NOCK(vm, val);
}



static void binop(struct netvm *vm, int op, uint64_t v1, uint64_t v2)
{
	uint64_t out;
	int amt;

	switch (op) {
	case NETVM_OC_ADD:
	case NETVM_OC_ADDI:
		out = v1 + v2;
		break;
	case NETVM_OC_SUB:
	case NETVM_OC_SUBI:
		out = v1 - v2;
		break;
	case NETVM_OC_MUL:
	case NETVM_OC_MULI:
		out = v1 * v2;
		break;
	case NETVM_OC_DIV:
	case NETVM_OC_DIVI:
		out = v1 / v2;
		break;
	case NETVM_OC_MOD:
	case NETVM_OC_MODI:
		out = v1 % v2;
		break;
	case NETVM_OC_SHL:
	case NETVM_OC_SHLI:
		out = v1 << (v2 & 0x3F);
		break;
	case NETVM_OC_SHR:
	case NETVM_OC_SHRI:
		out = v1 >> (v2 & 0x3F);
		break;
	case NETVM_OC_SHRA:
	case NETVM_OC_SHRAI:
		amt = v2 & 0x3F;
		out = (v1 >> amt) | -((v1 & 0x80000000) >> amt);
		break;
	case NETVM_OC_AND:
	case NETVM_OC_ANDI:
		out = v1 & v2;
		break;
	case NETVM_OC_OR:
	case NETVM_OC_ORI:
		out = v1 | v2;
		break;
	case NETVM_OC_XOR:
	case NETVM_OC_XORI:
		out = v1 ^ v2;
		break;
	case NETVM_OC_EQ:
	case NETVM_OC_EQI:
		out = v1 == v2;
		break;
	case NETVM_OC_NEQ:
	case NETVM_OC_NEQI:
		out = v1 != v2;
		break;
	case NETVM_OC_LT:
	case NETVM_OC_LTI:
		out = (int64_t)v1 < (int64_t)v2;
		break;
	case NETVM_OC_LE:
	case NETVM_OC_LEI:
		out = (int64_t)v1 <= (int64_t)v2;
		break;
	case NETVM_OC_GT:
	case NETVM_OC_GTI:
		out = (int64_t)v1 > (int64_t)v2;
		break;
	case NETVM_OC_GE:
	case NETVM_OC_GEI:
		out = (int64_t)v1 >= (int64_t)v2;
		break;
	case NETVM_OC_ULT:
	case NETVM_OC_ULTI:
		out = v1 < v2;
		break;
	case NETVM_OC_ULE:
	case NETVM_OC_ULEI:
		out = v1 <= v2;
		break;
	case NETVM_OC_UGT:
	case NETVM_OC_UGTI:
		out = v1 > v2;
		break;
	case NETVM_OC_UGE:
	case NETVM_OC_UGEI:
		out = v1 >= v2;
		break;
	default:
		out = 0;
		abort_unless(0);
	}

	/* All binary operations have at least one operand popped from */
	/* the stack.  So no need to check for stack bounds. */
	S_PUSH_NOCK(vm, out);
}


static void ni_binop(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t v1, v2;
	S_POP(vm, v2);
	S_POP(vm, v1);
	binop(vm, inst->op, v1, v2);
}


static void ni_binopi(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t v1, v2;
	v2 = inst->w;
	S_POP(vm, v1);
	binop(vm, inst->op, v1, v2);
}


static void ni_getcpt(struct netvm *vm)
{
	uint64_t cpi;

	S_POP(vm, cpi);
	FATAL(vm, NETVM_ERR_BADCOPROC, cpi >= NETVM_MAXCOPROC);
	if (vm->coprocs[cpi] == NULL) {
		S_PUSH(vm, NETVM_CPT_NONE);
	} else {
		S_PUSH(vm, vm->coprocs[cpi]->type);
	}
}


static void ni_bri(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t off = inst->w;

	off = sign_extend(off, 32);

	/* should be verified before start */
	abort_unless(vm->pc + off + 1 <= vm->ninst);

	if (inst->op != NETVM_OC_BRI) {
		uint64_t cond;
		S_POP(vm, cond);
		if (inst->op == NETVM_OC_BZI)
			cond = !cond;
		if (!cond)
			return;
	}
	/* ok to overflow number of instructions by 1: implied halt instruction */
	vm->pc += off;
}


static void ni_jmpi(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	/* Should be checked at validation time */
	abort_unless(inst->w + 1 <= vm->ninst);
	vm->pc = inst->w;
}


static void ni_halt(struct netvm *vm)
{
	vm->running = 0;
}


static void ni_cpop(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t cpi;
	uint64_t op;
	struct netvm_coproc *coproc;

	if (inst->op == NETVM_OC_CPOPI) {
		cpi = inst->x;
		op = inst->y;
	} else {
		S_POP(vm, cpi);
		S_POP(vm, op);
	}
	FATAL(vm, NETVM_ERR_BADCOPROC,
	      (cpi >= NETVM_MAXCOPROC) || ((coproc=vm->coprocs[cpi]) == NULL));
	FATAL(vm, NETVM_ERR_BADCPOP, op >= coproc->numops);
	(*coproc->ops[op])(vm, coproc, cpi);
}


static void ni_br(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t off;

	abort_unless(!vm->matchonly);
	S_POP(vm, off);
	FATAL(vm, NETVM_ERR_INSTADDR, (uint64_t)(vm->pc + off) >= vm->ninst);
	if (inst->op != NETVM_OC_BR) {
		uint64_t cond;
		S_POP(vm, cond);
		if (inst->op == NETVM_OC_BZ)
			cond = !cond;
		if (!cond)
			return;
	}
	/* ok to overflow number of instructions by 1: implied halt instruction */
	vm->pc += off;
}


static void ni_pushpc(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	S_PUSH(vm, (uint64_t)vm->pc + inst->w - 1);
}


static void ni_jmp(struct netvm *vm)
{
	uint64_t addr;
	S_POP(vm, addr);
	FATAL(vm, NETVM_ERR_INSTADDR, addr >= vm->ninst);
	vm->pc = addr;
}


static void ni_call(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t addr, narg, sslot;

	narg = inst->w;
	S_POP(vm, addr);
	FATAL(vm, NETVM_ERR_INSTADDR, addr >= vm->ninst);
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, narg));
	FATAL(vm, NETVM_ERR_STKOVFL, S_AVAIL(vm) < 2);
	sslot = vm->sp - narg;
	memmove(vm->stack + sslot + 2, vm->stack + sslot,
		narg * sizeof(vm->stack[0]));
	vm->stack[sslot] = vm->pc;
	vm->stack[sslot + 1] = vm->bp;
	vm->bp = sslot + 2;
	vm->sp += 2;
	vm->pc = addr;
}


static void ni_ret(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t addr, bp, narg, sslot;

	narg = inst->w;
	FATAL(vm, NETVM_ERR_IOVFL, (narg + 2 < narg));
	FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, narg) || (vm->bp < 2));
	sslot = vm->bp - 2;
	addr = vm->stack[sslot];
	bp = vm->stack[sslot + 1];
	FATAL(vm, NETVM_ERR_INSTADDR, addr >= vm->ninst);
	FATAL(vm, NETVM_ERR_STKOVFL, bp > vm->bp - 2);
	memmove(vm->stack + sslot, vm->stack + vm->sp - narg,
		narg * sizeof(vm->stack[0]));
	vm->sp = sslot + narg;
	vm->bp = bp;
	vm->pc = addr;
}


void netvm_stk2p(struct netvm *vm, byte_t *p, uint64_t val, int width)
{
	switch (width & 0x7F) {
	case 8: *p++ = val >> 56;
	case 7: *p++ = val >> 48;
	case 6: *p++ = val >> 40;
	case 5: *p++ = val >> 32;
	case 4: *p++ = val >> 24;
	case 3: *p++ = val >> 16;
	case 2: *p++ = val >> 8;
	case 1: *p = val;
		break;
	default:
		abort_unless(0);	/* should be checked at validation */
		VMERR(vm, NETVM_ERR_WIDTH);
	}
}


static void ni_st(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t addr;
	uint64_t val;
	int width;
	byte_t *p;

	width = inst->x;

	if ((inst->y & NETVM_SEG_ISPKT) == 0) {
		if (inst->op == NETVM_OC_ST) {
			S_POP(vm, addr);
		} else  {
			addr = inst->w;
		}
		netvm_get_mem_ptr(vm, inst->y, addr, 1, width & 0x7F, &p);
	} else {
		netvm_get_prp_ptr(vm, inst, (inst->op == NETVM_OC_ST), width,
				  &p);
	}

	if (!vm->error) {
		S_POP(vm, val);
		netvm_stk2p(vm, p, val, width);
	}
}


static void ni_move(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t saddr, daddr, len;
	byte_t *s, *d;

	S_POP(vm, len);
	S_POP(vm, daddr);
	S_POP(vm, saddr);

	FATAL(vm, NETVM_ERR_IOVFL, (saddr + len < len) || (daddr + len < len));
	netvm_get_seg_ptr(vm, inst->x, saddr, 0, len, &s);
	if (vm->error)
		return;
	netvm_get_seg_ptr(vm, inst->y, daddr, 1, len, &d);
	if (vm->error)
		return;
	memmove(d, s, len);
}


static void ni_pkswap(struct netvm *vm)
{
	int p1, p2;
	struct pktbuf *tmp;
	S_POP(vm, p2);
	S_POP(vm, p1);
	FATAL(vm, NETVM_ERR_PKTNUM, (p1 >= NETVM_MAXPKTS)
	      || (p2 >= NETVM_MAXPKTS));
	tmp = vm->packets[p1];
	vm->packets[p1] = vm->packets[p2];
	vm->packets[p2] = tmp;
}


static void ni_pknew(struct netvm *vm)
{
	struct netvm_prp_desc pd0;
	struct pktbuf *pnew;

	netvm_get_pd(vm, &pd0, 0);
	if (vm->error)
		return;

	FATAL(vm, NETVM_ERR_PKTNUM, pd0.pktnum >= NETVM_MAXPKTS);
	/* NOTE: ptype must be a PKDL_* value, not a PPT_* value */
	pnew = pkb_create(pd0.offset);
	FATAL(vm, NETVM_ERR_NOMEM, !pnew);
	pkb_free(vm->packets[pd0.pktnum]);
	vm->packets[pd0.pktnum] = pnew;
}


static void ni_pkcopy(struct netvm *vm)
{
	uint64_t pktnum, slot;
	struct pktbuf *pkb, *pnew;
	S_POP(vm, pktnum);
	FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
	S_POP(vm, slot);
	if (slot == pktnum)
		return;
	FATAL(vm, NETVM_ERR_PKTNUM, slot >= NETVM_MAXPKTS);
	pnew = pkb_copy(pkb);
	FATAL(vm, NETVM_ERR_NOMEM, !pnew);
	pkb_free(vm->packets[slot]);
	vm->packets[slot] = pnew;
}


static void ni_pksla(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct prparse *prp;

	prp = netvm_find_header(vm, &pd0, 0);
	if (vm->error)
		return;

	FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
	pkb_set_layer(vm->packets[pd0.pktnum], prp, inst->x);
}


static void ni_pkcla(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t pktnum;
	struct pktbuf *pkb;
	S_POP(vm, pktnum);
	FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
	pkb_clr_layer(pkb, inst->x);
}


static void ni_pkppsh(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct pktbuf *pkb;

	netvm_get_pd(vm, &pd0, 0);
	if (vm->error)
		return;
	FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pd0.pktnum]));
	/* XXX is this the right error? */
	if (inst->x) {	/* outer push */
		FATAL(vm, NETVM_ERR_NOMEM, pkb_wrapprp(pkb, pd0.ptype) < 0);
	} else {		/* inner push */
		FATAL(vm, NETVM_ERR_NOMEM, pkb_pushprp(pkb, pd0.ptype) < 0);
	}
}


static void ni_pkppop(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t pktnum;
	struct pktbuf *pkb;
	S_POP(vm, pktnum);
	FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
	/* width tells whether to pop from the front (non-zero) or back */
	pkb_popprp(pkb, inst->x);
}


static void ni_pkdel(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t pktnum;
	struct pktbuf *pkb;
	if (inst->op == NETVM_OC_PKDELI) {
		pktnum = inst->w;
	} else {
		S_POP(vm, pktnum);
	}
	FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
	pkb = vm->packets[pktnum];
	if (pkb) {
		pkb_free(pkb);
		vm->packets[pktnum] = NULL;
	}
}


static void ni_pkfxd(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint64_t pktnum;
	struct pktbuf *pkb;

	if (inst->op == NETVM_OC_PKFXDI) {
		pktnum = inst->w;
	} else {
		S_POP(vm, pktnum);
	}
	FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
	pkb_fix_dltype(pkb);
}


static void ni_pkpup(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct prparse *prp;

	prp = netvm_find_header(vm, &pd0, (inst->op == NETVM_OC_PKPUP));
	if (vm->error)
		return;
	FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
	prp_update(prp);
}


static void ni_pkfxl(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct pktbuf *pkb;
	struct prparse *prp;

	prp = netvm_find_header(vm, &pd0, (inst->op == NETVM_OC_PKFXL));
	if (vm->error)
		return;

	FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);

	if (prp_list_head(prp)) {
	        abort_unless(pd0.pktnum < NETVM_MAXPKTS);
		pkb = vm->packets[pd0.pktnum];
		abort_unless(pkb);
		if (pkb->layers[PKB_LAYER_XPORT])
			FATAL(vm, NETVM_ERR_FIXLEN,
			      prp_fix_len(pkb->layers[PKB_LAYER_XPORT]) < 0);
		if (pkb->layers[PKB_LAYER_NET])
			FATAL(vm, NETVM_ERR_FIXLEN,
			      prp_fix_len(pkb->layers[PKB_LAYER_NET]) < 0);
		if (pkb->layers[PKB_LAYER_DL])
			FATAL(vm, NETVM_ERR_FIXLEN,
			      prp_fix_len(pkb->layers[PKB_LAYER_DL]) < 0);
	} else {
		abort_unless(prp);
		FATAL(vm, NETVM_ERR_FIXLEN, prp_fix_len(prp) < 0);
	}
}


static void ni_pkfxc(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct pktbuf *pkb;
	struct prparse *prp;

	prp = netvm_find_header(vm, &pd0, (inst->op == NETVM_OC_PKFXC));
	if (vm->error)
		return;

	FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);

	if (prp_list_head(prp)) {
	        abort_unless(pd0.pktnum < NETVM_MAXPKTS);
		pkb = vm->packets[pd0.pktnum];
		abort_unless(pkb);
		if (pkb->layers[PKB_LAYER_XPORT])
			FATAL(vm, NETVM_ERR_CKSUM,
			      prp_fix_cksum(pkb->layers[PKB_LAYER_XPORT]) < 0);
		if (pkb->layers[PKB_LAYER_NET])
			FATAL(vm, NETVM_ERR_CKSUM,
			      prp_fix_cksum(pkb->layers[PKB_LAYER_NET]) < 0);
		if (pkb->layers[PKB_LAYER_DL])
			FATAL(vm, NETVM_ERR_CKSUM,
			      prp_fix_cksum(pkb->layers[PKB_LAYER_DL]) < 0);
	} else {
		abort_unless(prp);
		FATAL(vm, NETVM_ERR_CKSUM, prp_fix_cksum(prp) < 0);
	}
}


static void ni_pkins(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct pktbuf *pkb;
	uint64_t len;

	netvm_get_pd(vm, &pd0, 0);
	if (vm->error)
		return;
	FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pd0.pktnum]));
	S_POP(vm, len);
	FATAL(vm, NETVM_ERR_PKTINS, (len > (ulong)-1));
	FATAL(vm, NETVM_ERR_PKTINS,
	      prp_insert(&pkb->prp, pd0.offset, len, inst->x) < 0);
}


static void ni_pkcut(struct netvm *vm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_prp_desc pd0;
	struct pktbuf *pkb;
	uint64_t len;

	netvm_get_pd(vm, &pd0, 0);
	if (vm->error)
		return;
	FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pd0.pktnum]));
	S_POP(vm, len);
	FATAL(vm, NETVM_ERR_PKTINS, (len > (ulong)-1));
	FATAL(vm, NETVM_ERR_PKTCUT,
	      prp_cut(&pkb->prp, pd0.offset, len, inst->x) < 0);
}


static void ni_pkadj(struct netvm *vm)
{
	struct netvm_prp_desc pd0;
	struct prparse *prp;
	uint64_t val;
	uint oid;
	ulong amt;
	int rv;

	prp = netvm_find_header(vm, &pd0, 0);
	if (vm->error)
		return;

	FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
	S_POP(vm, val);
	amt = (ulong)val;
	if ((pd0.field < NETVM_PRP_OFF_BASE) ||
	    (prp_list_head(prp) &&
	     ((pd0.field == NETVM_PRP_SOFF) || (pd0.field == NETVM_PRP_EOFF))))
		VMERR(vm, NETVM_ERR_PRPFLD);
	oid = pd0.field - NETVM_PRP_OFF_BASE;
	rv = prp_adj_off(prp, oid, amt);
	FATAL(vm, NETVM_ERR_PRPADJ, rv < 0);
}


netvm_op g_netvm_ops[NETVM_OC_MAX + 1] = {
	ni_nop,			/* NOP */
	ni_pop,			/* POP */
	ni_popbp,		/* POPBP */
	ni_push,		/* PUSH */
	ni_pushhi,		/* PUSHHI */
	ni_zpush,		/* ZPUSH */
	ni_dup,			/* DUP */
	ni_swap,		/* SWAP */
	ni_ldbp,		/* LDBP */
	ni_ldbpi,		/* LDBPI */
	ni_stbp,		/* STBP */
	ni_stbpi,		/* STBPI */
	ni_pfe,			/* PFE */
	ni_pfe,			/* PFEI */
	ni_ldpf,		/* LDPF */
	ni_ldpf,		/* LDPFI */

	ni_ld,			/* LD */
	ni_ld,			/* LDI */

	ni_cmp,			/* CMP */
	ni_pcmp,		/* PCMP */
	ni_mskcmp,		/* MSKCMP */

	/* unary operations */
	ni_unop,		/* NOT */
	ni_unop,		/* INVERT */
	ni_unop,		/* TOBOOL */
	ni_unop,		/* POPL */
	ni_unop,		/* NLZ */
	ni_unop,		/* SIGNX */

	/* binary operations */
	ni_binop,		/* ADD */
	ni_binopi,		/* ADDI */
	ni_binop,		/* SUB */
	ni_binopi,		/* SUBI */
	ni_binop,		/* MUL */
	ni_binopi,		/* MULI */
	ni_binop,		/* DIV */
	ni_binopi,		/* DIVI */
	ni_binop,		/* MOD */
	ni_binopi,		/* MODI */
	ni_binop,		/* SHL */
	ni_binopi,		/* SHLI */
	ni_binop,		/* SHR */
	ni_binopi,		/* SHRI */
	ni_binop,		/* SHRA */
	ni_binopi,		/* SHRAI */
	ni_binop,		/* AND */
	ni_binopi,		/* ANDI */
	ni_binop,		/* OR */
	ni_binopi,		/* ORI */
	ni_binop,		/* XOR */
	ni_binopi,		/* XORI */
	ni_binop,		/* EQ */
	ni_binopi,		/* EQI */
	ni_binop,		/* NEQ */
	ni_binopi,		/* NEQI */
	ni_binop,		/* LT */
	ni_binopi,		/* LTI */
	ni_binop,		/* LE */
	ni_binopi,		/* LEI */
	ni_binop,		/* GT */
	ni_binopi,		/* GTI */
	ni_binop,		/* GE */
	ni_binopi,		/* GEI */
	ni_binop,		/* ULT */
	ni_binopi,		/* ULTI */
	ni_binop,		/* ULE */
	ni_binopi,		/* ULEI */
	ni_binop,		/* UGT */
	ni_binopi,		/* UGTI */
	ni_binop,		/* UGE */
	ni_binopi,		/* UGEI */

	ni_getcpt,		/* GETCPT */
	ni_cpop,		/* CPOPI */
	ni_bri,			/* BRI */
	ni_bri,			/* BNZI */
	ni_bri,			/* BZI */
	ni_jmpi,		/* JMPI */
	ni_halt,		/* HALT */

	/* non-matching-only */
	ni_cpop,		/* CPOP */
	ni_br,			/* BR */
	ni_br,			/* BNZ */
	ni_br,			/* BZ */
	ni_pushpc,		/* PUSHPC */
	ni_jmp,			/* JMP */
	ni_call,		/* CALL */
	ni_ret,			/* RET */

	ni_st,			/* ST */
	ni_st,			/* STI */

	ni_move,		/* MOVE */

	ni_pkswap,		/* PKSWAP */
	ni_pknew,		/* PKNEW */
	ni_pkcopy,		/* PKCOPY */
	ni_pksla,		/* PKSLA */
	ni_pkcla,		/* PKCLA */
	ni_pkppsh,		/* PKPPSH */
	ni_pkppop,		/* PKPPOP */

	ni_pkdel,		/* PKDEL */
	ni_pkdel,		/* PKDELI */
	ni_pkfxd,		/* PKFXD */
	ni_pkfxd,		/* PKFXDI */
	ni_pkpup,		/* PKPUP */
	ni_pkpup,		/* PKPUPI */
	ni_pkfxl,		/* PKFXL */
	ni_pkfxl,		/* PKFXLI */
	ni_pkfxc,		/* PKFXC */
	ni_pkfxc,		/* PKFXCI */

	ni_pkins,		/* PKINS */
	ni_pkcut,		/* PKCUT */
	ni_pkadj,		/* PKADJ */
};


void netvm_init(struct netvm *vm, uint64_t * stack, uint ssz,
		byte_t * mem, uint memsz)
{
	int i;
	abort_unless(vm && stack && ssz > 0 && ssz + 1 > 0);
	vm->stack = stack;
	vm->stksz = ssz;
	vm->mem = mem;
	vm->memsz = memsz;
	vm->rosegoff = memsz;
	vm->inst = NULL;
	vm->ninst = 0;
	vm->pc = 0;
	vm->sp = 0;
	vm->bp = 0;
	vm->matchonly = 0;
	memset(vm->packets, 0, sizeof(vm->packets));
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		vm->coprocs[i] = NULL;
}


int netvm_validate(struct netvm *vm)
{
	struct netvm_inst *inst;
	uint64_t i, maxi, newpc;

	if (!vm || !vm->stack || (vm->rosegoff > vm->memsz) || !vm->inst ||
	    (vm->ninst < 0) || (vm->ninst > MAXINST))
		return NETVM_ERR_UNINIT;
	maxi = vm->matchonly ? NETVM_OC_MAX_MATCH : NETVM_OC_MAX;
	for (i = 0; i < vm->ninst; i++) {
		inst = &vm->inst[i];
		if (inst->op > maxi)
			return NETVM_ERR_BADOP;

		/* validate branch immediate instructions */
		if ((inst->op == NETVM_OC_BRI) ||
		    (inst->op == NETVM_OC_BNZI) ||
		    (inst->op == NETVM_OC_BZI) ||
		    (inst->op == NETVM_OC_JMPI)) {
			if (inst->op == NETVM_OC_JMPI)
				newpc = inst->w + 1;
			else
				newpc = sign_extend(inst->w, 32) + 1 + i;
			if (newpc > vm->ninst)
				return NETVM_ERR_BRADDR;
			if (vm->matchonly && (newpc <= i))
				return NETVM_ERR_BRMONLY;

		/* validate widths for load/store operations */
		} else if ((inst->op == NETVM_OC_LD) ||
		           (inst->op == NETVM_OC_LDI) ||
		           (inst->op == NETVM_OC_ST) ||
		           (inst->op == NETVM_OC_STI) ||
			   (inst->op == NETVM_OC_POPL) ||
			   (inst->op == NETVM_OC_NLZ) ||
			   (inst->op == NETVM_OC_SIGNX)) {
			if (((inst->x & 0x7F) < 1) || ((inst->x & 0x7F) > 8))
				return NETVM_ERR_BADWIDTH;

		/* Validate layer indices for set/clear layer operations */
		} else if ((inst->op == NETVM_OC_PKSLA) ||
			   (inst->op == NETVM_OC_PKCLA)) {
			if (inst->x >= PKB_LAYER_NUM)
				return NETVM_ERR_BADLAYER;

		/* Validate coprocessor operations where cpi and cpop are */
		/* specified in the instruction itself. */
		} else if (inst->op == NETVM_OC_CPOPI) {
			int rv;
			struct netvm_coproc *cp;
			if ((inst->x >= NETVM_MAXCOPROC) ||
			    ((cp = vm->coprocs[inst->x]) == NULL))
				return NETVM_ERR_BADCP;
			if (inst->y >= cp->numops)
				return NETVM_ERR_BADCP;
			if ((cp->validate != NULL)
			    && ((rv = (*cp->validate)(inst, vm)) < 0))
				return rv;
		}
	}
	return 0;
}


/* set the read-only segment offset for the VM */
int netvm_setrooff(struct netvm *vm, uint rooff)
{
	abort_unless(vm);
	if (rooff > vm->memsz)
		return -1;
	vm->rosegoff = rooff;
	return 0;
}


/* set up netvm code */
int netvm_setcode(struct netvm *vm, struct netvm_inst *inst, uint ni)
{
	abort_unless(vm && inst);
	vm->inst = inst;
	vm->ninst = ni;
	return netvm_validate(vm);
}


int netvm_set_coproc(struct netvm *vm, int cpi, struct netvm_coproc *coproc)
{
	int rv;

	abort_unless(vm && cpi < NETVM_MAXCOPROC);

	if ((coproc != NULL) && (coproc->regi != NULL))
		if ((rv = (*coproc->regi)(coproc, vm, cpi)) < 0)
			return rv;

	vm->coprocs[cpi] = coproc;
	return 0;
}


void netvm_set_matchonly(struct netvm *vm, int matchonly)
{
	abort_unless(vm);
	vm->matchonly = matchonly;
}


int netvm_loadpkt(struct netvm *vm, struct pktbuf *pkb, int slot)
{
	pkb_free(vm->packets[slot]);
	vm->packets[slot] = pkb;
	return 0;
}


struct pktbuf *netvm_clrpkt(struct netvm *vm, int slot, int keeppkb)
{
	struct pktbuf *pkb = NULL;
	if ((slot >= 0) && (slot < NETVM_MAXPKTS) && 
	    (pkb = vm->packets[slot])) {
		if (keeppkb) {
			/* adjust header and trailer slack space and copy    */
			/* back to packet buffer metadata before returning.  */
			prp_adj_unused(&pkb->prp);
		} else {
			pkb_free(pkb);
			pkb = NULL;
		}
		vm->packets[slot] = NULL;
	}
	return pkb;
}


/* clear memory up through read-only segment */
void netvm_clrmem(struct netvm *vm)
{
	abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst &&
		     vm->ninst >= 0 && vm->ninst <= MAXINST);
	if (vm->mem)
		memset(vm->mem, 0, vm->rosegoff);
}


/* discard all packets */
void netvm_clrpkts(struct netvm *vm)
{
	int i;
	abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst &&
		     vm->ninst >= 0 && vm->ninst <= MAXINST);
	for (i = 0; i < NETVM_MAXPKTS; ++i) {
		pkb_free(vm->packets[i]);
		vm->packets[i] = NULL;
	}
}


void netvm_reset_coprocs(struct netvm *vm)
{
	int i;
	struct netvm_coproc *cp;

	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		cp = vm->coprocs[i];
		if (cp != NULL && cp->reset != NULL)
			(*cp->reset)(cp);
	}
}


/* reinitialize for running but with same packet and memory state */
void netvm_restart(struct netvm *vm)
{
	abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst &&
		     vm->ninst >= 0 && vm->ninst <= MAXINST);
	vm->pc = 0;
	vm->sp = 0;
	vm->bp = 0;
}


/* clear memory, set pc <= 0, discard packets, reset coprocessors */
void netvm_reset(struct netvm *vm)
{
	/* assume sanity checks in the called functions */
	netvm_clrmem(vm);
	netvm_clrpkts(vm);
	netvm_reset_coprocs(vm);
	netvm_restart(vm);
}


/* 0 if run ok and no retval, 1 if run ok and stack not empty, */
/* -1 on error, -2 if max cycle count reached */
int netvm_run(struct netvm *vm, int maxcycles, uint64_t *rv)
{
	struct netvm_inst *inst;

	abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst &&
		     vm->ninst >= 0 && vm->ninst <= MAXINST);
	vm->error = 0;
	vm->running = 1;

	if (vm->pc >= vm->ninst) {
		if (vm->pc == vm->ninst) { 
			vm->running = 0;
		} else {
			vm->error = NETVM_ERR_INSTADDR;
			return -1;
		}
	}

	while (vm->running) {
		inst = &vm->inst[vm->pc];
		(*g_netvm_ops[inst->op])(vm);
		if (vm->error == 0) {
			vm->pc++;
			if (maxcycles > 0) {
				if (--maxcycles == 0)
					vm->running = 0;
			} else if (vm->pc >= vm->ninst) {
				vm->running = 0;
			} 
		} else {
			vm->running = 0;
		}
	}

	if (maxcycles == 0) {
		return -2;
	} else if (vm->error) {
		return -1;
	} else if (vm->sp == 0) {
		return 0;
	} else {
		if (rv)
			*rv = vm->stack[vm->sp - 1];
		return 1;
	}
}


static const char *val_error_strings[-(NETVM_ERR_MIN) + 1] = {
	"ok",
	"VM not properly initialized",
	"Invalid opcode",
	"Invalid jump address",
	"Invalid branch/jump in matchonly mode",
	"Invalid layer index",
	"Invalid width field",
	"Coprocessor instruction invalid",
	"Coprocessor-specific validation error",
};


static const char *rt_error_strings[NETVM_ERR_MAX+1] = {
	"ok",
	"unimplemented instruction",
	"stack overflow",
	"stack underflow",
	"invalid width field",
	"instruction address error",
	"memory address error",
	"packet address error",
	"write attempt to read-only segment",
	"bad packet index",
	"attempt to access non-existant packet",
	"attempt to access non-existant header",
	"attempt to access non-existant header field",
	"erroneously formed header descriptor",
	"bad header index",
	"bad header field",
	"bad header layer in instruction",
	"error fixing length",
	"error fixing checksum",
	"error inserting into packet",
	"error cutting data from packet",
	"error adjusting header field",
	"out of memory",
	"integer overflow",
	"bad co-processor index",
	"co-processor operation error"
};


const char *netvm_estr(int error)
{
	if ((error < NETVM_ERR_MIN) || (error > NETVM_ERR_MAX)) {
		return "Unknown";
	} else if (error < 0) {
		return val_error_strings[-error];
	} else {
		return rt_error_strings[error];
	}
}
