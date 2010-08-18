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

/* 
 * find header based on packet number, header type, and index.  So (3,8,1) 
 * means find the 2nd (0-based counting) TCP (PPT_TCP == 8) header in the 4th
 * packet.
 */
static struct prparse *find_header(struct netvm *vm, 
                                   struct netvm_prp_desc *pd)
{
  struct metapkt *pkt;
  struct prparse *prp;
  int n = 0;
  if ( pd->pktnum >= NETVM_MAXPKTS )
    return NULL;
  pkt = vm->packets[pd->pktnum];
  if ( !pkt )
    return NULL;
  abort_unless(pkt->pkb && pkt->headers);
  prp = pkt->headers;
  do {
    if ( (pd->ptype == PPT_NONE) || (pd->ptype == prp->type) ) {
      if ( n == pd->idx )
        return prp;
      ++n;
    }
    prp = prp_next(prp);
  } while ( prp != pkt->headers );
  return NULL;
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
  uint32_t v;
  S_POP(vm, v);
}


static void ni_push(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  S_PUSH(vm, inst->val);
}


static void ni_dup(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t val;
  if ( inst->flags & NETVM_IF_NEGBPOFF ) {
    FATAL(vm, NETVM_ERR_STKUNDF, vm->bp <= inst->val);
    val = vm->stack[vm->bp - inst->val - 1];
  } else { 
    FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, inst->val+1));
    if ( inst->flags & NETVM_IF_BPOFF ) {
      val = vm->stack[vm->bp + 1 + inst->val];
    } else {
      val = S_GET(vm, inst->val);
    }
  }
  S_PUSH(vm, val);
}


static void ni_swap(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t tmp = (inst->width > inst->val) ? inst->width : inst->val;
  FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, tmp+1));
  if ( inst->flags & NETVM_IF_BPOFF ) {
    tmp = vm->stack[vm->bp + 1 + inst->width];
    vm->stack[vm->bp + 1 + inst->width] = vm->stack[vm->bp + 1 + inst->val];
    vm->stack[vm->bp + 1 + inst->val] = tmp;
  } else {
    tmp = S_GET(vm, inst->width);
    S_SET(vm, inst->width, S_GET(vm, inst->val));
    S_SET(vm, inst->val, tmp);
  }
}


static void ni_ldmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t val;
  register int width = inst->width;
  register uint32_t addr;
  FATAL(vm, NETVM_ERR_MEMADDR, !vm->mem || !vm->memsz);
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  if ( inst->flags & NETVM_IF_RDONLY ) {
    FATAL(vm, NETVM_ERR_IOVFL, addr + vm->rosegoff < addr);
    addr += vm->rosegoff;
  }
  FATAL(vm, NETVM_ERR_MRDONLY, addr > vm->memsz || addr + width > vm->memsz);
  if ( ISSIGNED(inst) )
    width = -width;
  switch(width) {
  case -1: val = (int32_t)*(int8_t *)(vm->mem + addr); break;
  case -2: val = (int32_t)*(int16_t *)(vm->mem + addr); break;
  case -4: val = (int32_t)*(int32_t *)(vm->mem + addr); break;
  case 1: val = *(uint8_t *)(vm->mem + addr); break;
  case 2: val = *(uint16_t *)(vm->mem + addr); break;
  case 4: val = *(uint32_t *)(vm->mem + addr); break;
  default:
    abort_unless(0); /* should be checked at validation time happen */
    VMERR(vm, NETVM_ERR_WIDTH);
  }
  S_PUSH(vm, val);
}


static void ni_stmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t val;
  register int width = inst->width;
  register uint32_t addr;
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  FATAL(vm, NETVM_ERR_MEMADDR, addr > vm->memsz || addr + width > vm->memsz);
  S_POP(vm, val);
  switch(width) {
  case 1: *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: *(uint32_t *)(vm->mem + addr) = val; break;
  default:
    abort_unless(0);  /* should be checked at validation time */
    VMERR(vm, NETVM_ERR_WIDTH);
  }
}


static void get_pd(struct netvm *vm, struct netvm_inst *inst,
                   struct netvm_prp_desc *pd)
{
  uint32_t val;
  if ( IMMED(inst) ) {
    val = inst->val;
    pd->pktnum = 0;
    pd->ptype = (val >> 24) & 0xff;
    pd->idx = (val >> 21) & 0x7;
    pd->field = (val >> 17) & 0xf;
    pd->offset = val & 0x1ffff;
  } else { 
    S_POP(vm, val);
    pd->pktnum = (val >> 28) & 0xf;
    pd->ptype = (val >> 20) & 0xff;
    pd->idx = (val >> 12) & 0xff;
    pd->field = val & 0xfff;
    S_POP(vm, pd->offset);
  }
}


static void get_prp_info(struct netvm *vm, struct netvm_inst *inst, 
                         struct netvm_prp_desc *pd, uint32_t *addr, 
                         struct prparse **prpp)
{
  int width;
  struct prparse *prp;
  struct metapkt *pkt;

  get_pd(vm, inst, pd);
  if ( vm->error )
    return;
  width = inst->width;
  FATAL(vm, NETVM_ERR_IOVFL, (pd->offset + width < pd->offset));

  if ( pd->ptype == NETVM_PRP_LAYER ) {
    FATAL(vm, NETVM_ERR_PRPIDX, pd->idx > MPKT_LAYER_MAX);
    FATAL(vm, NETVM_ERR_PKTNUM, (pd->pktnum >= NETVM_MAXPKTS));
    FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pd->pktnum]));
    prp = pkt->layer[pd->idx];
  } else {
    FATAL(vm, NETVM_ERR_PRPFLD, !NETVM_ISPRPOFF(pd->field));
    prp = find_header(vm, pd);
  }
  FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);

  switch(pd->field) {
  case NETVM_PRP_HOFF:
    FATAL(vm, NETVM_ERR_PKTADDR, pd->offset + width > prp_hlen(prp));
    *addr = prp->hoff + pd->offset;
    break;
  case NETVM_PRP_POFF:
    FATAL(vm, NETVM_ERR_PKTADDR, pd->offset + width > prp_plen(prp));
    *addr = prp->poff + pd->offset;
    break;
  case NETVM_PRP_TOFF:
    FATAL(vm, NETVM_ERR_PKTADDR, pd->offset + width > prp_tlen(prp));
    *addr = prp->toff + pd->offset;
    break;
  case NETVM_PRP_EOFF:
  default:
    VMERR(vm, NETVM_ERR_PRPFLD);
    break;
  }
  *prpp = prp;
}


static void ni_ldpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;
  uint32_t addr;
  uint32_t val;

  get_prp_info(vm, inst, &pd0, &addr, &prp);
  if ( vm->error )
    return;

  switch(inst->width) {
  case 1: 
    val = *(uint8_t *)(prp->data + addr); 
    if ( inst->flags & NETVM_IF_IPHLEN ) { 
      val = (val & 0xf) << 2;
    } else if ( inst->flags & NETVM_IF_TCPHLEN ) {
      val = (val & 0xf0) >> 2;
    } else { 
      if ( ISSIGNED(inst) )
        val |= -(val & 0x80);
    }
    break;
  case 2: 
    val = *(uint16_t *)(prp->data + addr); 
    if ( inst->flags & NETVM_IF_TOHOST )
      val = ntoh16(val);
    if ( ISSIGNED(inst) )
      val |= -(val & 0x8000);
    break;
  case 4: 
    val = *(uint32_t *)(prp->data + addr); 
    if ( inst->flags & NETVM_IF_TOHOST )
      val = ntoh32(val);
    if ( ISSIGNED(inst) )
      val |= -(val & 0x80000000);
    break;
  default:
    abort_unless(0);  /* should be checked at validation time */
    VMERR(vm, NETVM_ERR_WIDTH);
  }
  S_PUSH(vm, val);
}


static void ni_ldpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }

  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  if ( inst->opcode == NETVM_OC_LDPEXST ) {
    S_PUSH(vm, vm->packets[pktnum] != NULL);
    return;
  }
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));

  if ( inst->opcode == NETVM_OC_LDCLASS ) {
    S_PUSH(vm, pkt->pkb->pkb_class);
  } else if ( inst->opcode == NETVM_OC_LDTSSEC ) {
    S_PUSH(vm, pkt->pkb->pkb_tssec);
  } else {
    abort_unless(inst->opcode == NETVM_OC_LDTSNSEC);
    S_PUSH(vm, pkt->pkb->pkb_tsnsec);
  }
}


static void ni_ldprpf(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;

  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  FATAL(vm, NETVM_ERR_PRPFLD, !NETVM_PRPFLDOK(pd0.field));
  if ( pd0.ptype == NETVM_PRP_LAYER ) {
    FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
    FATAL(vm, NETVM_ERR_NOPKT, !vm->packets[pd0.pktnum]);
    FATAL(vm, NETVM_ERR_PRPIDX, (pd0.idx > MPKT_LAYER_MAX));
    prp = vm->packets[pd0.pktnum]->layer[pd0.idx];
    /* Special case to make it easy to check for layer headers */
  } else {
    prp = find_header(vm, &pd0);
  }
  if ( !prp ) {
    if ( pd0.field == NETVM_PRP_TYPE ) {
      S_PUSH(vm, PPT_NONE);
      return;
    } else { 
      VMERR(vm, NETVM_ERR_NOPRP);
    }
  }

  switch (pd0.field) {
  case NETVM_PRP_HOFF: S_PUSH(vm, prp->hoff); break;
  case NETVM_PRP_POFF: S_PUSH(vm, prp->poff); break;
  case NETVM_PRP_TOFF: S_PUSH(vm, prp->toff); break;
  case NETVM_PRP_EOFF: S_PUSH(vm, prp->eoff); break;
  case NETVM_PRP_HLEN: S_PUSH(vm, prp_hlen(prp)); break;
  case NETVM_PRP_PLEN: S_PUSH(vm, prp_plen(prp)); break;
  case NETVM_PRP_TLEN: S_PUSH(vm, prp_tlen(prp)); break;
  case NETVM_PRP_LEN:  S_PUSH(vm, prp_totlen(prp)); break;
  case NETVM_PRP_ERR:  S_PUSH(vm, prp->error); break;
  case NETVM_PRP_TYPE: S_PUSH(vm, prp->type); break;
  case NETVM_PRP_PRFLD: {
    size_t off, len;
    unsigned fid, idx;
    fid = pd0.offset & 0xffff;
    idx = (pd0.offset >> 16) & 0xffff;
    off = prp_get_field(prp, fid, idx, &len);
    S_PUSH(vm, (uint32_t)off); 
    S_PUSH(vm, (uint32_t)len); 
  } break;
  default:
    abort_unless(0);
  }
}


static void ni_blkmv(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t saddr, daddr, len;
  if ( IMMED(inst) )
    len = inst->val;
  else
    S_POP(vm, len);
  S_POP(vm, daddr);
  S_POP(vm, saddr);
  FATAL(vm, NETVM_ERR_IOVFL, (saddr + len < len) || (daddr + len < len));
  FATAL(vm, NETVM_ERR_NOMEM, vm->mem == NULL);
  FATAL(vm, NETVM_ERR_MEMADDR, 
        (saddr + len > vm->memsz) || (daddr + len > vm->memsz));
  memmove(vm->mem + daddr, vm->mem + saddr, len);
}


static void ni_blkpmv(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  uint32_t poff, maddr, len;
  struct metapkt *pkt;
  struct prparse *prp;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  S_POP(vm, len);
  S_POP(vm, maddr);
  S_POP(vm, poff);
  FATAL(vm, NETVM_ERR_IOVFL, (len + maddr < len) || (len + poff < len));
  prp = pkt->headers;
  FATAL(vm, NETVM_ERR_PKTADDR, 
        (poff < prp->poff) || (poff + len > prp_totlen(prp)));
  FATAL(vm, NETVM_ERR_MEMADDR, !vm->mem || (maddr + len > vm->memsz));
  if ( inst->opcode == NETVM_OC_BULKP2M )
    memcpy(vm->mem + maddr, prp->data + poff, len);
  else
    memcpy(prp->data + poff, vm->mem + maddr, len);
}


static void ni_memcmp(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr1, addr2, len, nbytes, val;
  if ( IMMED(inst) )
    len = inst->val;
  else
    S_POP(vm, len);
  S_POP(vm, addr1);
  S_POP(vm, addr2);
  if ( inst->opcode == NETVM_OC_MEMCMP )
    nbytes = len;
  else
    nbytes = (len + 7) >> 3;
  FATAL(vm, NETVM_ERR_IOVFL, 
        (addr1 + nbytes < nbytes) || (addr2 + nbytes < nbytes));
  FATAL(vm, NETVM_ERR_MEMADDR, 
        (addr1 + nbytes > vm->memsz) || (addr2 + nbytes > vm->memsz));
  if ( inst->opcode == NETVM_OC_PFXCMP ) {
    byte_t *p1 = vm->mem + addr1;
    byte_t *p2 = vm->mem + addr2;
    val = 0;
    while ( len > 8 ) {
      if (*p1 != *p2) {
        val = (*p1 < *p2) ? (0 - (uint32_t)1) : 1;
        S_PUSH(vm, val);
        break;
      }
      ++p1; ++p2; len -= 8;
    }
    if ( (len > 0) && !val ) {
      byte_t b1 = *p1 & -(1 << (8 - len));
      byte_t b2 = *p2 & -(1 << (8 - len));
      if ( b1 != b2 )
        val = (b1 < b2) ? (0 - (uint32_t)1) : 1;
    }
  } else {
    val = memcmp(vm->mem + addr1, vm->mem + addr2, len);
  }
  S_PUSH(vm, val);
}


static void ni_maskeq(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t saddr, daddr, maddr, len;
  byte_t *src, *dst, *mask;
  if ( IMMED(inst) )
    len = inst->val;
  else
    S_POP(vm, len);
  S_POP(vm, maddr);
  S_POP(vm, daddr);
  S_POP(vm, saddr);
  FATAL(vm, NETVM_ERR_IOVFL, 
        (saddr + len < len) || (daddr + len < len) || (maddr + len < len));
  FATAL(vm, NETVM_ERR_MEMADDR,
        (saddr + len > vm->memsz) || (daddr + len > vm->memsz) ||
        (maddr + len > vm->memsz));
  src = (byte_t *)vm->mem + saddr;
  dst = (byte_t *)vm->mem + daddr;
  mask = (byte_t *)vm->mem + maddr;
  while ( len > 0 ) {
    if ( (*src++ & *mask) != (*dst++ & *mask) ) {
      S_PUSH(vm, 0);
      return;
    }
    ++mask;
    --len;
  }
  S_PUSH(vm, 1);
}


static void ni_numop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t out, v1, v2;
  int amt;
  if ( (inst->opcode < NETVM_OC_NOT) || (inst->opcode > NETVM_OC_SIGNX)) {
    if ( IMMED(inst) )  {
      v2 = inst->val;
    } else {
      S_POP(vm, v2);
    }
  }
  S_POP(vm, v1);
  switch (inst->opcode) {
  case NETVM_OC_NOT: out = !v1; break;
  case NETVM_OC_INVERT: out = ~v1; break;
  case NETVM_OC_TOBOOL: out = v1 != 0; break;
  case NETVM_OC_POPL: /* fall through */
  case NETVM_OC_NLZ: 
    if ( inst->width < sizeof(uint32_t) )
      v1 &= (1 << (inst->width * 8)) - 1;
    if ( inst->opcode == NETVM_OC_POPL ) {
      out = pop_32(v1);
    } else {
      out = nlz_32(v1) - 32 + inst->width * 8;
    }
    break;
  case NETVM_OC_TONET: 
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    }
    break;
  case NETVM_OC_TOHOST: 
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    }
    break;
  case NETVM_OC_SIGNX: 
    case 1: out = v1 | -(v1 & 0x80); break;
    case 2: out = v1 | -(v1 & 0x8000); break;
    break;
  case NETVM_OC_ADD: out = v1 + v2; break;
  case NETVM_OC_SUB: out = v1 - v2; break;
  case NETVM_OC_MUL: out = v1 * v2; break;
  case NETVM_OC_DIV: out = v1 / v2; break;
  case NETVM_OC_MOD: out = v1 % v2; break;
  case NETVM_OC_SHL: out = v1 << (v2 & 0x1F); break;
  case NETVM_OC_SHR: out = v1 >> (v2 & 0x1F); break;
  case NETVM_OC_SHRA:
    amt = v2 & 0x1F;
    out = (v1 >> amt) | -((v1 & 0x80000000) >> amt);
    break;
  case NETVM_OC_AND: out = v1 & v2; break;
  case NETVM_OC_OR: out = v1 | v2; break;
  case NETVM_OC_XOR: out = v1 ^ v2; break;
  case NETVM_OC_EQ: out = v1 == v2; break;
  case NETVM_OC_NEQ: out = v1 != v2; break;
  case NETVM_OC_LT: out = v1 < v2; break;
  case NETVM_OC_LE: out = v1 <= v2; break;
  case NETVM_OC_GT: out = v1 > v2; break;
  case NETVM_OC_GE: out = v1 >= v2; break;
  case NETVM_OC_SLT: out = (int32_t)v1 < (int32_t)v2; break;
  case NETVM_OC_SLE: out = (int32_t)v1 <= (int32_t)v2; break;
  case NETVM_OC_SGT: out = (int32_t)v1 > (int32_t)v2; break;
  case NETVM_OC_SGE: out = (int32_t)v1 >= (int32_t)v2; break;
  default:
    abort_unless(0);
  }
  S_PUSH(vm, out);
}


static void ni_hasprp(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  uint32_t val;
  struct metapkt *pkt;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  if ( pd0.ptype == NETVM_PRP_LAYER ) {
    FATAL(vm, NETVM_ERR_LAYER, pd0.idx > MPKT_LAYER_MAX);
    FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
    FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pd0.pktnum]));
    val = pkt->layer[pd0.idx] != NULL;
  } else {
    val = find_header(vm, &pd0) != NULL;
  }
  S_PUSH(vm, val);
}


static void ni_getcpt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t cpi;
  if ( IMMED(inst) ) {
    cpi = inst->width;
  } else {
    S_POP(vm, cpi);
  }
  FATAL(vm, NETVM_ERR_BADCOPROC, cpi >= NETVM_MAXCOPROC);
  if ( vm->coprocs[cpi] == NULL ) {
    S_PUSH(vm, NETVM_CPT_NONE);
  } else {
    S_PUSH(vm, vm->coprocs[cpi]->type);
  }
}


static void ni_cpop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t cpi;
  uint8_t op;
  struct netvm_coproc *coproc;
  if ( IMMED(inst) ) {
    cpi = inst->width;
  } else {
    S_POP(vm, cpi);
  }
  op = (inst->flags >> 8) & 0xFF;
  FATAL(vm, NETVM_ERR_BADCOPROC, 
        (cpi >= NETVM_MAXCOPROC) || ((coproc = vm->coprocs[cpi]) == NULL));
  FATAL(vm, NETVM_ERR_BADCPOP, op >= coproc->numops);
  (*coproc->ops[op])(vm, coproc, cpi);
}


static void ni_halt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  vm->running = 0;
  vm->error = inst->val;
}


static void ni_branch(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t off;
  if ( IMMED(inst) ) {
    off = inst->val;
  } else {
    abort_unless(!vm->matchonly);
    S_POP(vm, off);
    FATAL(vm, NETVM_ERR_INSTADDR, vm->pc + off + 1 > vm->ninst);
  }
  if ( inst->opcode != NETVM_OC_BR ) {
    uint32_t cond;
    S_POP(vm, cond);
    if ( inst->opcode == NETVM_OC_BZ )
      cond = !cond;
    if ( !cond )
      return;
  }
  /* ok to overflow number of instructions by 1: implied halt instruction */
  vm->pc += off;
}


static void ni_jump(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr;
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  FATAL(vm, NETVM_ERR_INSTADDR, addr + 1 > vm->ninst);
  vm->pc = addr;
}


static void ni_call(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr, narg, sslot;
  if ( IMMED(inst) ) {
    narg = inst->val;
  } else {
    S_POP(vm, narg);
  }
  S_POP(vm, addr);
  FATAL(vm, NETVM_ERR_INSTADDR, addr + 1 > vm->ninst);
  FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, narg)); 
  FATAL(vm, NETVM_ERR_STKOVFL, S_AVAIL(vm) < 2);
  sslot = vm->sp - narg;
  memmove(vm->stack + sslot + 2, vm->stack + sslot, narg*sizeof(vm->stack[0]));
  vm->stack[sslot] = vm->pc;
  vm->stack[sslot+1] = vm->bp;
  vm->bp = sslot + 2;
  vm->sp += 2;
  vm->pc = addr;
}


static void ni_return(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr, bp, narg, sslot;
  if ( IMMED(inst) ) {
    narg = inst->val;
  } else {
    S_POP(vm, narg);
  }
  FATAL(vm, NETVM_ERR_IOVFL, (narg + 2 < narg));
  FATAL(vm, NETVM_ERR_STKUNDF, !S_HAS(vm, narg) || (vm->bp < 2));
  sslot = vm->bp - 2;
  addr = vm->stack[sslot];
  bp = vm->stack[sslot + 1];
  FATAL(vm, NETVM_ERR_INSTADDR, addr + 1 > vm->ninst);
  FATAL(vm, NETVM_ERR_STKOVFL, bp > vm->bp - 2);
  memmove(vm->stack + sslot, vm->stack + vm->sp - narg, 
          narg*sizeof(vm->stack[0]));
  vm->sp -= (vm->sp - narg) - sslot;
  vm->bp = bp;
  vm->pc = addr;
}


static void ni_stpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;
  uint32_t addr;
  uint32_t val;

  get_prp_info(vm, inst, &pd0, &addr, &prp);
  if ( vm->error )
    return;
  S_POP(vm, val);

  switch(inst->width) {
  case 1: {
    *(uint8_t *)(prp->data + addr) = val;
  } break;
  case 2: {
    uint16_t v = val;
    if ( inst->flags & NETVM_IF_TOHOST )
      v = hton16(v);
    *(uint16_t *)(prp->data + addr) = v;
  } break;
  case 4: {
    uint32_t v = val;
    if ( inst->flags & NETVM_IF_TOHOST )
      v = hton32(v);
    *(uint32_t *)(prp->data + addr) = v;
  } break;
  default:
    abort_unless(0); /* should be checked in get_prp_info() */
  }
}


static void ni_stpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  uint32_t val;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  S_POP(vm, val);
  if ( inst->opcode == NETVM_OC_STCLASS ) {
    pkt->pkb->pkb_class = val;
  } else if ( inst->opcode == NETVM_OC_STTSSEC ) {
    pkt->pkb->pkb_tssec = val;
  } else {
    abort_unless(inst->opcode == NETVM_OC_STTSNSEC);
    pkt->pkb->pkb_tsnsec = val;
  }
}


static void ni_pktswap(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int p1, p2;
  struct metapkt *tmp;
  if ( IMMED(inst) ) {
    p1 = inst->width;
    p2 = inst->val;
  } else {
    S_POP(vm, p2);
    S_POP(vm, p1);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (p1 >= NETVM_MAXPKTS) || (p2 >= NETVM_MAXPKTS));
  tmp = vm->packets[p1];
  vm->packets[p1] = vm->packets[p2];
  vm->packets[p2] = tmp;
}


static void ni_pktnew(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct metapkt *pnew;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  FATAL(vm, NETVM_ERR_PKTNUM, pd0.pktnum >= NETVM_MAXPKTS);
  /* NOTE: ptype must be a PKDL_* value, not a PPT_* value */
  pnew = metapkt_new(pd0.offset, pd0.ptype);
  FATAL(vm, NETVM_ERR_NOMEM, !pnew);
  metapkt_free(vm->packets[pd0.pktnum], 1);
  vm->packets[pd0.pktnum] = pnew;
}


static void ni_pktcopy(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum, slot;
  struct metapkt *pkt, *pnew;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  S_POP(vm, slot);
  FATAL(vm, NETVM_ERR_PKTNUM, slot >= NETVM_MAXPKTS);
  pnew = metapkt_copy(pkt);
  FATAL(vm, NETVM_ERR_NOMEM, !pnew);
  metapkt_free(vm->packets[slot], 1);
  vm->packets[slot] = pnew;
}


static void ni_pktdel(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
  pkt = vm->packets[pktnum];
  if ( pkt ) {
    metapkt_free(pkt, 1);
    vm->packets[pktnum] = NULL;
  }
}


static void ni_setlayer(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  prp = find_header(vm, &pd0);
  FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
  metapkt_set_layer(vm->packets[pd0.pktnum], prp, inst->width);
}


static void ni_clrlayer(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  metapkt_clr_layer(vm->packets[pktnum], inst->width);
}


static void ni_prppush(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct metapkt *pkt;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pd0.pktnum]));
  /* XXX is this the right error? */
  if ( inst->width ) { /* outer push */
    FATAL(vm, NETVM_ERR_NOMEM, metapkt_wrapprp(pkt, pd0.ptype) < 0);
  } else { /* inner push */
    FATAL(vm, NETVM_ERR_NOMEM, metapkt_pushprp(pkt, pd0.ptype) < 0);
  }
}


static void ni_prppop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  /* width tells whether to pop from the front (non-zero) or back */
  metapkt_popprp(pkt, inst->width);
}


static void ni_prpup(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  prp = find_header(vm, &pd0);
  FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
  prp_update(prp);
}


static void ni_fixdlt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  metapkt_fixdlt(pkt);
}


static void ni_fixlen(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  /* TODO: allow more precise selection of which lengths to fix */
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  if ( pkt->layer[MPKT_LAYER_XPORT] )
    FATAL(vm, NETVM_ERR_FIXLEN, prp_fix_len(pkt->layer[MPKT_LAYER_XPORT]) < 0);
  if ( pkt->layer[MPKT_LAYER_NET] )
    FATAL(vm, NETVM_ERR_FIXLEN, prp_fix_len(pkt->layer[MPKT_LAYER_NET]) < 0);
  if ( pkt->layer[MPKT_LAYER_LINK] )
    FATAL(vm, NETVM_ERR_FIXLEN, prp_fix_len(pkt->layer[MPKT_LAYER_LINK]) < 0);
}


static void ni_fixcksum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  /* TODO: allow more precise selection of which checksums to fix */
  FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pktnum]));
  if ( pkt->layer[MPKT_LAYER_XPORT] )
    FATAL(vm, NETVM_ERR_CKSUM, prp_fix_cksum(pkt->layer[MPKT_LAYER_XPORT]) < 0);
  if ( pkt->layer[MPKT_LAYER_NET] )
    FATAL(vm, NETVM_ERR_CKSUM, prp_fix_cksum(pkt->layer[MPKT_LAYER_NET]) < 0);
  if ( pkt->layer[MPKT_LAYER_LINK] )
    FATAL(vm, NETVM_ERR_CKSUM, prp_fix_cksum(pkt->layer[MPKT_LAYER_LINK]) < 0);
}


static void ni_prpins(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct metapkt *pkt;
  uint32_t len;
  int moveup;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  moveup = inst->flags & NETVM_IF_MOVEUP;
  FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pd0.pktnum]));
  S_POP(vm, len);
  FATAL(vm, NETVM_ERR_PKTINS,
        prp_insert(pkt->headers, pd0.offset, len, moveup) < 0);
}


static void ni_prpcut(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct metapkt *pkt;
  uint32_t len;
  int moveup;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  moveup = inst->flags & NETVM_IF_MOVEUP;
  FATAL(vm, NETVM_ERR_PKTNUM, (pd0.pktnum >= NETVM_MAXPKTS));
  FATAL(vm, NETVM_ERR_NOPKT, !(pkt=vm->packets[pd0.pktnum]));
  S_POP(vm, len);
  FATAL(vm, NETVM_ERR_PKTCUT, 
        prp_cut(pkt->headers, pd0.offset, len, moveup) < 0);
}


static void ni_prpadj(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_prp_desc pd0;
  struct prparse *prp;
  uint32_t val;
  ptrdiff_t amt;
  int rv;
  get_pd(vm, inst, &pd0);
  if ( vm->error )
    return;
  prp = find_header(vm, &pd0);
  FATAL(vm, NETVM_ERR_NOPRP, prp == NULL);
  S_POP(vm, val);
  amt = (int32_t)val;
  switch(pd0.field) {
  case NETVM_PRP_HOFF: rv = prp_adj_start(prp, amt); break;
  case NETVM_PRP_POFF: rv = prp_adj_poff(prp, amt); break;
  case NETVM_PRP_TOFF: rv = prp_adj_toff(prp, amt); break;
  case NETVM_PRP_EOFF: rv = prp_adj_end(prp, amt); break;
  case NETVM_PRP_PLEN: rv = prp_adj_plen(prp, amt); break;
  default:
    VMERR(vm, NETVM_ERR_PRPFLD);
  }
  FATAL(vm, NETVM_ERR_PRPADJ, rv < 0);
}


netvm_op g_netvm_ops[NETVM_OC_MAX+1] = {
  ni_nop,
  ni_pop,
  ni_push,
  ni_dup,
  ni_swap,
  ni_ldmem,
  ni_stmem,
  ni_ldpkt,
  ni_ldpmeta, /* LDPEXST */
  ni_ldpmeta, /* LDCLASS */
  ni_ldpmeta, /* LDTSSEC */
  ni_ldpmeta, /* LDTSNSEC */
  ni_ldprpf,
  ni_blkmv, /* BULMP2M */
  ni_blkpmv, /* BULKP2M */
  ni_memcmp, /* MEMCMP */
  ni_memcmp, /* PFXCMP */
  ni_maskeq, /* MASKEQ*/
  ni_numop, /* NOT */
  ni_numop, /* INVERT */
  ni_numop, /* TOBOOL */
  ni_numop, /* POPL */
  ni_numop, /* NLZ */
  ni_numop, /* TONET */
  ni_numop, /* TOHOST */
  ni_numop, /* SIGNX */
  ni_numop, /* ADD */
  ni_numop, /* SUB */
  ni_numop, /* MUL */
  ni_numop, /* DIV */
  ni_numop, /* MOD */
  ni_numop, /* SHL */
  ni_numop, /* SHR */
  ni_numop, /* SHRA */
  ni_numop, /* AND */
  ni_numop, /* OR */
  ni_numop, /* XOR */
  ni_numop, /* EQ */
  ni_numop, /* NEQ */
  ni_numop, /* LT */
  ni_numop, /* LE */
  ni_numop, /* GT */
  ni_numop, /* GE */
  ni_numop, /* SLT */
  ni_numop, /* SLE */
  ni_numop, /* SGT */
  ni_numop, /* SGE */
  ni_hasprp,
  ni_getcpt,
  ni_cpop,
  ni_halt,
  ni_branch, /* BR */
  ni_branch, /* BNZ */
  ni_branch, /* BZ */

  /* non-matching-only */
  ni_jump,
  ni_call,
  ni_return,
  ni_stpkt,
  ni_stpmeta, /* STCLASS */
  ni_stpmeta, /* STTSSEC */
  ni_stpmeta, /* STTSNSEC */
  ni_blkpmv, /* BULKP2M */
  ni_pktswap,
  ni_pktnew,
  ni_pktcopy,
  ni_pktdel,
  ni_setlayer,
  ni_clrlayer,
  ni_prppush,
  ni_prppop,
  ni_prpup,
  ni_fixdlt,
  ni_fixlen,
  ni_fixcksum,
  ni_prpins,
  ni_prpcut,
  ni_prpadj,
};


void netvm_init(struct netvm *vm, uint32_t *stack, uint32_t ssz,
                byte_t *mem, uint32_t memsz)
{
  int i;
  abort_unless(vm && stack && ssz > 0 );
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
  for ( i = 0; i < NETVM_MAXCOPROC; ++i )
    vm->coprocs[i] = NULL;
}


int netvm_validate(struct netvm *vm)
{
  struct netvm_inst *inst;
  uint32_t i, maxi, newpc;

  if ( !vm || !vm->stack || (vm->rosegoff > vm->memsz) || !vm->inst ||
       (vm->ninst < 0) || (vm->ninst > MAXINST) )
    return NETVM_ERR_UNINIT;
  maxi = vm->matchonly ? NETVM_OC_MAX_MATCH : NETVM_OC_MAX;
  for ( i = 0; i < vm->ninst; i++ ) {
    inst = &vm->inst[i];
    if ( inst->opcode > maxi )
      return NETVM_ERR_BADOP;
    if ( (inst->opcode == NETVM_OC_BR) || (inst->opcode == NETVM_OC_BNZ) ||
         (inst->opcode == NETVM_OC_BZ) || (inst->opcode == NETVM_OC_JUMP) ) {
      if ( IMMED(inst) ) {
        if ( inst->opcode == NETVM_OC_JUMP )
          newpc = inst->val + 1;
        else
          newpc = inst->val + 1 + i;
        if ( newpc > vm->ninst )
          return NETVM_ERR_BRADDR;
        if ( vm->matchonly && (newpc <= i) )
          return NETVM_ERR_BRMONLY;
      } else {
        if ( vm->matchonly )
          return NETVM_ERR_BRMONLY;
      }
    } else if ( (inst->opcode == NETVM_OC_LDMEM) ||
                (inst->opcode == NETVM_OC_STMEM) ||
                (inst->opcode == NETVM_OC_LDPKT) ||
                (inst->opcode == NETVM_OC_STPKT) ||
                (inst->opcode == NETVM_OC_POPL) ||
                (inst->opcode == NETVM_OC_NLZ) ||
                (inst->opcode == NETVM_OC_TONET) ||
                (inst->opcode == NETVM_OC_TOHOST) ||
                (inst->opcode == NETVM_OC_SIGNX)
              ) {
      if ( (inst->width != 1) && (inst->width != 2) && (inst->width != 4) )
        return NETVM_ERR_BADWIDTH;
    } else if ( (inst->opcode == NETVM_OC_SETLAYER) || 
                (inst->opcode == NETVM_OC_CLRLAYER) ) {
      if ( inst->width >= MPKT_LAYER_MAX )
        return NETVM_ERR_BADLAYER;
    } else if ( inst->opcode == NETVM_OC_CPOP ) {
      if ( IMMED(inst) ) {
        int rv;
        struct netvm_coproc *cp;
        if ( (inst->width >= NETVM_MAXCOPROC) || 
             ((cp = vm->coprocs[inst->width]) == NULL) )
          return NETVM_ERR_BADCP;
        if ( (cp->validate != NULL) && ((rv = (*cp->validate)(inst, vm)) < 0) )
          return rv;
      } else if ( vm->matchonly ) { 
        return NETVM_ERR_BADCP;
      }
    }
  }
  return 0;
}


/* set the read-only segment offset for the VM */
int netvm_setrooff(struct netvm *vm, uint32_t rooff)
{
  abort_unless(vm);
  if ( rooff > vm->memsz )
    return -1;
  vm->rosegoff = rooff;
  return 0;
}


/* set up netvm code */
int netvm_setcode(struct netvm *vm, struct netvm_inst *inst, uint32_t ni)
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

  if ( (coproc != NULL) && (coproc->regi != NULL) )
    if ( (rv = (*coproc->regi)(coproc, vm, cpi)) < 0 )
      return rv;

  vm->coprocs[cpi] = coproc;
  return 0;
}


void netvm_set_matchonly(struct netvm *vm, int matchonly)
{
  abort_unless(vm);
  vm->matchonly = matchonly;
}


int netvm_loadpkt(struct netvm *vm, struct pktbuf *p, int slot)
{
  struct metapkt *pkt;
  if ( (slot < 0) || (slot >= NETVM_MAXPKTS) || !(pkt = pktbuf_to_metapkt(p)) )
    return -1;
  metapkt_free(vm->packets[slot], 1);
  vm->packets[slot] = pkt;
  return 0;
}


struct pktbuf *netvm_clrpkt(struct netvm *vm, int slot, int keeppkb)
{
  struct metapkt *pkt;
  struct pktbuf *pkb = NULL;
  if ( (slot >= 0) && (slot < NETVM_MAXPKTS) && (pkt = vm->packets[slot]) ) {
    if ( keeppkb )
      pkb = pkt->pkb;
    metapkt_free(pkt, !keeppkb);
    vm->packets[slot] = NULL;
  }
  return pkb;
}


/* clear memory up through read-only segment */
void netvm_clrmem(struct netvm *vm)
{
  abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst && 
               vm->ninst >= 0 && vm->ninst <= MAXINST);
  if ( vm->mem )
    memset(vm->mem, 0, vm->rosegoff);
}


/* discard all packets */
void netvm_clrpkts(struct netvm *vm)
{
  int i;
  abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst && 
               vm->ninst >= 0 && vm->ninst <= MAXINST);
  for ( i = 0; i < NETVM_MAXPKTS; ++i ) {
    metapkt_free(vm->packets[i], 1);
    vm->packets[i] = NULL;
  }
}


void netvm_reset_coprocs(struct netvm *vm)
{
  int i;
  struct netvm_coproc *cp; 

  for ( i = 0; i < NETVM_MAXCOPROC; ++i ) {
    cp = vm->coprocs[i];
    if ( cp != NULL && cp->reset != NULL )
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


/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err */
int netvm_run(struct netvm *vm, int maxcycles, uint32_t *rv)
{
  struct netvm_inst *inst;

  abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst && 
               vm->ninst >= 0 && vm->ninst <= MAXINST);
  vm->error = 0;
  vm->running = 1;
  
  if ( vm->pc < 0 || vm->pc > vm->ninst )
    vm->error = 1;
  else if ( vm->pc == vm->ninst + 1 )
    vm->running = 0;

  while ( vm->running && !vm->error && (maxcycles != 0) ) {
    inst = &vm->inst[vm->pc];
    (*g_netvm_ops[inst->opcode])(vm);
    ++vm->pc;
    if ( vm->pc >= vm->ninst ) {
      vm->running = 0;
      if ( vm->pc != vm->ninst ) 
        vm->error = 1;
    }
    if ( maxcycles > 0 )
      --maxcycles;
  }

  if ( maxcycles == 0 ) {
    return -2;
  } else if ( vm->error ) {
    return -1;
  } else if ( vm->sp == 0 ) {
    return 0;
  } else { 
    if ( rv )
      *rv = vm->stack[vm->sp-1];
    return 1;
  }
}


static const char *val_error_strings[] = { 
  "ok",
  "Invalid opcode",
  "Invalid jump address",
  "Invalid branch/jump in matchonly mode",
  "Invalid layer index",
  "Invalid width field",
  "Coprocessor instruction invalid"
};


static const char *rt_error_strings[] = { 
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
  if ( (error < NETVM_ERR_MIN) || (error > NETVM_ERR_MAX) ) {
    return "Unknown";
  } else if ( error < 0 ) {
    return val_error_strings[-error];
  } else {
    return rt_error_strings[error];
  }
}


