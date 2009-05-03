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

/* purely to set a breakpoint during debugging */
static int dbgabrt()
{
  return 1;
}

#define MAXINST         0x7ffffffe
#define IMMED(inst) ((inst)->flags & NETVM_IF_IMMED)
#define ISSIGNED(inst) ((inst)->flags & NETVM_IF_SIGNED)

#define VMERR(__vm) do { __vm->error = 1; dbgabrt(); return; } while (0)

#define FATAL(__vm, __cond) \
  if (__cond) { __vm->error = 1; dbgabrt(); return; }

#define S_EMPTY(__vm)           (__vm->sp == 0)
#define S_HAS(__vm, __n)        (__vm->sp >= __n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)

#define S_TOP(__vm, __v)                                                \
  do {                                                                  \
    FATAL((__vm), S_EMPTY(__vm));                                       \
    __v = __vm->stack[__vm->sp-1];                                      \
  } while (0)

/* __n is a 0-based index from the top of the stack */
#define S_GET(__vm, __n)        (__vm->stack[__vm->sp - __n - 1])
#define S_SET(__vm, __n, __val) (__vm->stack[__vm->sp - __n - 1] = __val)

#define S_POP(__vm, __v)                                                \
  do {                                                                  \
    FATAL((__vm), S_EMPTY(__vm));                                       \
    __v = __vm->stack[--__vm->sp];                                      \
  } while (0)

#define S_PUSH(__vm, __v)                                               \
  do {                                                                  \
    FATAL((__vm), S_FULL(__vm));                                        \
    __vm->stack[__vm->sp++] = (__v);                                    \
  } while (0)

#define CKWIDTH(__vm, __w) FATAL((__vm), !__w || (__w & (__w - 1)) || (__w > 4))


typedef void (*netvm_op)(struct netvm *vm);


/* 
 * find header based on packet number, header type, and index.  So (3,8,1) 
 * means find the 2nd (0-based counting) TCP (PPT_TCP == 8) header in the 4th
 * packet.
 */
static struct hdr_parse *find_header(struct netvm *vm, 
                                     struct netvm_hdr_desc *hd)
{
  struct metapkt *pkt;
  struct hdr_parse *hdr;
  int n = 0;
  if ( hd->pktnum >= NETVM_MAXPKTS )
    return NULL;
  pkt = vm->packets[hd->pktnum];
  if ( !pkt )
    return NULL;
  abort_unless(pkt->pkb && pkt->headers);
  hdr = pkt->headers;
  do {
    if ( (hd->htype == PPT_NONE) || (hd->htype == hdr->type) ) {
      if ( n == hd->idx )
        return hdr;
      ++n;
    }
    hdr = hdr_child(hdr);
  } while ( hdr != pkt->headers );
  return NULL;
}


static void ni_unimplemented(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  if ( vm->outport )
    emit_format(vm->outport, "Instruction %d not implemented\n", inst->opcode);
  vm->error = 1;
}


static void ni_nop(struct netvm *vm)
{
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
  FATAL(vm, !S_HAS(vm, inst->val+1));
  val = S_GET(vm, inst->val);
  S_PUSH(vm, val);
}


static void ni_swap(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t tmp = (inst->width > inst->val) ? inst->width : inst->val;
  FATAL(vm, !S_HAS(vm, tmp + 1));
  tmp = S_GET(vm, inst->width);
  S_SET(vm, inst->width, S_GET(vm, inst->val));
  S_SET(vm, inst->val, tmp);
}


static void ni_ldmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t val;
  register int width = inst->width;
  register uint32_t addr;
  FATAL(vm, !vm->mem || !vm->memsz);
  CKWIDTH(vm, width);   /* TODO: check these during validation */
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  if ( inst->flags & NETVM_IF_RDONLY ) {
    FATAL(vm, addr + vm->rosegoff < addr);
    addr += vm->rosegoff;
  }
  FATAL(vm, addr > vm->memsz || addr + width > vm->memsz);
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
    VMERR(vm);
  }
  S_PUSH(vm, val);
}


static void ni_stmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t val;
  register int width = inst->width;
  register uint32_t addr;
  CKWIDTH(vm, width);
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  FATAL(vm, addr > vm->memsz || addr + width > vm->memsz);
  S_POP(vm, val);
  switch(width) {
  case 1: *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: *(uint32_t *)(vm->mem + addr) = val; break;
  default:
    VMERR(vm);
  }
}


static void get_hd(struct netvm *vm, struct netvm_inst *inst,
                   struct netvm_hdr_desc *hd)
{
  uint32_t val;
  if ( IMMED(inst) ) {
    val = inst->val;
    hd->pktnum = 0;
    hd->htype = (val >> 24) & 0xff;
    hd->idx = (val >> 21) & 0x7;
    hd->field = (val >> 17) & 0xf;
    hd->offset = val & 0x1ffff;
  } else { 
    S_POP(vm, val);
    hd->pktnum = (val >> 28) & 0xf;
    hd->htype = (val >> 20) & 0xff;
    hd->idx = (val >> 12) & 0xff;
    hd->field = val & 0xfff;
    S_POP(vm, hd->offset);
  }
}


static void get_hdr_info(struct netvm *vm, struct netvm_inst *inst, 
                         struct netvm_hdr_desc *hd, uint32_t *addr, 
                         struct hdr_parse **hdrp)
{
  int width;
  struct hdr_parse *hdr;
  struct metapkt *pkt;

  get_hd(vm, inst, hd);
  if ( vm->error )
    return;
  width = inst->width;
  CKWIDTH(vm, width);

  if ( hd->htype == NETVM_HDLAYER ) {
    FATAL(vm, hd->idx > NETVM_HDI_MAX);
    FATAL(vm, (hd->pktnum >= NETVM_MAXPKTS) || !(pkt=vm->packets[hd->pktnum]));
    hdr = pkt->layer[hd->idx];
  } else {
    FATAL(vm, (hd->offset + width < hd->offset) || !NETVM_ISHDROFF(hd->field));
    hdr = find_header(vm, hd);
  }
  FATAL(vm, hdr == NULL);

  switch(hd->field) {
  case NETVM_HDR_HOFF:
    FATAL(vm, hd->offset + width > hdr_hlen(hdr));
    *addr = hdr->hoff + hd->offset;
    break;
  case NETVM_HDR_POFF:
    FATAL(vm, hd->offset + width > hdr_plen(hdr));
    *addr = hdr->poff + hd->offset;
    break;
  case NETVM_HDR_TOFF:
    FATAL(vm, hd->offset + width > hdr_tlen(hdr));
    *addr = hdr->toff + hd->offset;
    break;
  case NETVM_HDR_EOFF:
  default:
    VMERR(vm);
    break;
  }
  *hdrp = hdr;
}


static void ni_ldpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  uint32_t addr;
  uint32_t val;

  get_hdr_info(vm, inst, &hd0, &addr, &hdr);
  if ( vm->error )
    return;

  switch(inst->width) {
  case 1: 
    val = *(uint8_t *)(hdr->data + addr); 
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
    val = *(uint16_t *)(hdr->data + addr); 
    if ( inst->flags & NETVM_IF_TOHOST )
      val = ntoh16(val);
    if ( ISSIGNED(inst) )
      val |= -(val & 0x8000);
    break;
  case 4: 
    val = *(uint32_t *)(hdr->data + addr); 
    if ( inst->flags & NETVM_IF_TOHOST )
      val = ntoh32(val);
    if ( ISSIGNED(inst) )
      val |= -(val & 0x80000000);
    break;
  default:
    VMERR(vm);
  }
  S_PUSH(vm, val);
}


static void ni_ldpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  if ( inst->opcode == NETVM_OC_LDCLASS ) {
    S_PUSH(vm, pkt->pkb->pkt_class);
  } else if ( inst->opcode == NETVM_OC_LDTSSEC ) {
    S_PUSH(vm, pkt->pkb->pkt_tssec);
  } else {
    abort_unless(inst->opcode == NETVM_OC_LDTSNSEC);
    S_PUSH(vm, pkt->pkb->pkt_tsnsec);
  }
}


static void ni_ldhdrf(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;

  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  FATAL(vm, !NETVM_HDRFLDOK(hd0.field));
  if ( hd0.htype == NETVM_HDLAYER ) {
    FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || (hd0.idx > NETVM_HDI_MAX));
    FATAL(vm, vm->packets[hd0.pktnum] == NULL);
    hdr = vm->packets[hd0.pktnum]->layer[hd0.idx];
    /* Special case to make it easy to check for layer headers */
  } else {
    hdr = find_header(vm, &hd0);
  }
  if ( !hdr ) {
    if ( hd0.field == NETVM_HDR_TYPE ) {
      S_PUSH(vm, PPT_NONE);
      return;
    } else { 
      VMERR(vm);
    }
  }

  switch (hd0.field) {
  case NETVM_HDR_HOFF: S_PUSH(vm, hdr->hoff); break;
  case NETVM_HDR_POFF: S_PUSH(vm, hdr->poff); break;
  case NETVM_HDR_TOFF: S_PUSH(vm, hdr->toff); break;
  case NETVM_HDR_EOFF: S_PUSH(vm, hdr->eoff); break;
  case NETVM_HDR_HLEN: S_PUSH(vm, hdr_hlen(hdr)); break;
  case NETVM_HDR_PLEN: S_PUSH(vm, hdr_plen(hdr)); break;
  case NETVM_HDR_TLEN: S_PUSH(vm, hdr_tlen(hdr)); break;
  case NETVM_HDR_LEN:  S_PUSH(vm, hdr_totlen(hdr)); break;
  case NETVM_HDR_ERR:  S_PUSH(vm, hdr->error); break;
  case NETVM_HDR_TYPE: S_PUSH(vm, hdr->type); break;
  case NETVM_HDR_PRFLD: {
    size_t off, len;
    unsigned fid, idx;
    fid = hd0.offset & 0xffff;
    idx = (hd0.offset >> 16) & 0xffff;
    off = hdr_get_field(hdr, fid, idx, &len);
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
  FATAL(vm, (saddr + len < len) || (daddr + len < len));
  FATAL(vm, (saddr + len >= vm->memsz) || (daddr + len >= vm->memsz));
  memmove(vm->mem + saddr, vm->mem + daddr, len);
}


static void ni_blkpmv(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  uint32_t poff, maddr, len;
  struct metapkt *pkt;
  struct hdr_parse *hdr;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  S_POP(vm, len);
  S_POP(vm, maddr);
  S_POP(vm, poff);
  FATAL(vm, (len + maddr < len) || (len + poff < len)); /* overflow */
  hdr = pkt->headers;
  FATAL(vm, (poff < hdr->poff) || (poff + len > hdr_totlen(hdr)));
  FATAL(vm, !vm->mem || (maddr + len > vm->memsz));
  if ( inst->opcode == NETVM_OC_BULKP2M )
    memcpy(vm->mem + maddr, hdr->data + poff, len);
  else
    memcpy(hdr->data + poff, vm->mem + maddr, len);
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
  FATAL(vm, (addr1 + nbytes < nbytes) || (addr2 + nbytes < nbytes));
  FATAL(vm, (addr1 + nbytes >= vm->memsz) || (addr2 + nbytes >= vm->memsz));
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
  FATAL(vm, (saddr + len < len) || (daddr + len < len) || (maddr + len < len));
  FATAL(vm, (saddr + len >= vm->memsz) || (daddr + len >= vm->memsz) ||
            (maddr + len >= vm->memsz));
  src = (byte_t *)vm->mem + saddr;
  dst = (byte_t *)vm->mem + daddr;
  mask = (byte_t *)vm->mem + maddr;
  while ( len > 0 ) {
    if ( (*src++ & *mask) != (*dst++ & *mask++) ) {
      S_PUSH(vm, 0);
      return;
    }
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
    CKWIDTH(vm, inst->width);
    if ( inst->width < sizeof(uint32_t) )
      v1 &= (1 << (inst->width * 8)) - 1;
    if ( inst->opcode == NETVM_OC_POPL )
      out = pop_32(v1);
    else
      out = nlz_32(v1);
    break;
  case NETVM_OC_TONET: 
    CKWIDTH(vm, inst->width);
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    }
    break;
  case NETVM_OC_TOHOST: 
    CKWIDTH(vm, inst->width);
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    }
    break;
  case NETVM_OC_SIGNX: 
    CKWIDTH(vm, inst->width);
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


static void ni_hashdr(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  uint32_t val;
  struct metapkt *pkt;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  if ( hd0.htype == NETVM_HDLAYER ) {
    FATAL(vm, hd0.idx > NETVM_HDI_MAX);
    FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || !(pkt=vm->packets[hd0.pktnum]));
    val = pkt->layer[hd0.idx] != NULL;
  } else {
    val = find_header(vm, &hd0) != NULL;
  }
  S_PUSH(vm, val);
}


static void ni_halt(struct netvm *vm)
{
  vm->running = 0;
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
    FATAL(vm, vm->pc + off + 1 > vm->ninst);
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
  FATAL(vm, addr + 1 > vm->ninst);
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
  FATAL(vm, addr + 1 > vm->ninst);
  FATAL(vm, !S_HAS(vm, narg) || S_FULL(vm));
  sslot = vm->sp - narg;
  memmove(vm->stack + sslot + 1, vm->stack + sslot, narg*sizeof(vm->stack[0]));
  vm->stack[sslot] = vm->pc;
  ++vm->sp;
  vm->pc = addr;
}


static void ni_return(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr, narg, sslot;
  if ( IMMED(inst) ) {
    narg = inst->val;
  } else {
    S_POP(vm, narg);
  }
  FATAL(vm, (narg + 1 < narg) || !S_HAS(vm, narg + 1));
  sslot = vm->sp - narg - 1;
  addr = vm->stack[sslot];
  FATAL(vm, addr + 1 > vm->ninst);
  memmove(vm->stack + sslot, vm->stack + sslot + 1, narg*sizeof(vm->stack[0]));
  --vm->sp;
  vm->pc = addr;
}


static void ni_prnum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  char fmtbuf[12];
  register int nwidth = inst->width;
  register int swidth = inst->val;
  uint32_t val;

  abort_unless(vm->outport);    /* should be guaranteed by netvm_init() */
  CKWIDTH(vm, nwidth); /* TODO: check during validation */
  FATAL(vm, swidth > 64 || swidth < 0); /* to prevent overflow of fmtbuf */

  switch (inst->opcode) {
  case NETVM_OC_PRBIN: 
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT32"b", swidth);
    else
      sprintf(fmtbuf, "%%"FMT32"b");
    break;
  case NETVM_OC_PROCT:
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT32"o", swidth);
    else
      sprintf(fmtbuf, "%%"FMT32"o");
    break;
  case NETVM_OC_PRDEC:
    if ( swidth ) {
      if ( ISSIGNED(inst) )
        sprintf(fmtbuf, "%%0%d"FMT32"d", swidth);
      else
        sprintf(fmtbuf, "%%0%d"FMT32"u", swidth);
    } else { 
      if ( ISSIGNED(inst) )
        sprintf(fmtbuf, "%%"FMT32"d");
      else
        sprintf(fmtbuf, "%%"FMT32"u");
    }
    break;
  case NETVM_OC_PRHEX:
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT32"x", swidth);
    else
      sprintf(fmtbuf, "%%"FMT32"x");
    break;
  default:
    abort_unless(0);
  }

  S_POP(vm, val);
  /* mask out all irrelevant bits */
  if ( nwidth < 4 )
    val &= ~((1 << (nwidth * 8)) - 1);
  /* sign extend the result if we are printing a signed decimal */
  if ( ISSIGNED(inst) && (inst->opcode == NETVM_OC_PRDEC) )
    val |= -(val & (1 << (nwidth * 8 - 1)));
  emit_format(vm->outport, fmtbuf, val);
}


static void ni_prip(struct netvm *vm)
{
  uint32_t val;
  byte_t *bp = (byte_t *)&val;
  abort_unless(vm->outport);
  S_POP(vm, val);
  /* Assumes network byte order */
  emit_format(vm->outport, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]);
}


static void ni_preth(struct netvm *vm)
{
  uint32_t val;
  byte_t *bp = (byte_t *)&val;
  abort_unless(vm->outport);
  S_POP(vm, val);
  /* Assumes network byte order */
  emit_format(vm->outport, "%02x:%02x:%02x:%02x:%02x:%02x", 
              bp[0], bp[1], bp[2], bp[3], bp[4], bp[5]);
}


static void ni_pripv6(struct netvm *vm)
{
  uint32_t vhi, vlo;
  byte_t *bhi = (byte_t *)&vhi, *blo = (byte_t *)&vlo;
  abort_unless(vm->outport);
  S_POP(vm, vlo);
  S_POP(vm, vhi);
  /* TODO: use the compression */
  emit_format(vm->outport, 
      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
      bhi[0], bhi[1], bhi[2], bhi[3], bhi[4], bhi[5], bhi[6], bhi[7],
      blo[0], blo[1], blo[2], blo[3], blo[4], blo[5], blo[6], blo[7]);
}


/* strings are stored with a 1-byte length prefix: no null terminators */
static void ni_prstr(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr, len;
  abort_unless(vm->outport);
  if ( IMMED(inst) ) {
    addr = inst->val;
    len = inst->width;
  } else {
    S_POP(vm, len);
    S_POP(vm, addr);
  }
  FATAL(vm, !vm->mem || !vm->memsz || addr >= vm->memsz);
  FATAL(vm, addr + len > vm->memsz || addr + len < addr);
  emit_raw(vm->outport, vm->mem + addr, len);
}


static void ni_stpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  uint32_t addr;
  uint32_t val;

  get_hdr_info(vm, inst, &hd0, &addr, &hdr);
  if ( vm->error )
    return;
  S_POP(vm, val);

  switch(inst->width) {
  case 1: {
    *(uint8_t *)(hdr->data + addr) = val;
  } break;
  case 2: {
    uint16_t v = val;
    if ( inst->flags & NETVM_IF_TOHOST )
      v = hton16(v);
    *(uint16_t *)(hdr->data + addr) = v;
  } break;
  case 4: {
    uint32_t v = val;
    if ( inst->flags & NETVM_IF_TOHOST )
      v = hton32(v);
    *(uint32_t *)(hdr->data + addr) = v;
  } break;
  default:
    abort_unless(0); /* should be checked in get_hdr_info() */
  }
}


static void ni_stpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  uint32_t val;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  S_POP(vm, val);
  if ( inst->opcode == NETVM_OC_STCLASS ) {
    pkt->pkb->pkt_class = val;
  } else if ( inst->opcode == NETVM_OC_STTSSEC ) {
    pkt->pkb->pkt_tssec = val;
  } else {
    abort_unless(inst->opcode == NETVM_OC_STTSNSEC);
    pkt->pkb->pkt_tsnsec = val;
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
  FATAL(vm, (p1 >= NETVM_MAXPKTS) || (p2 >= NETVM_MAXPKTS));
  tmp = vm->packets[p1];
  vm->packets[p1] = vm->packets[p2];
  vm->packets[p2] = tmp;
}


static void ni_pktnew(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct metapkt *pnew;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  FATAL(vm, hd0.pktnum >= NETVM_MAXPKTS);
  /* NOTE: htype must be a PKDL_* value, not a PPT_* value */
  pnew = metapkt_new(hd0.offset, hd0.htype);
  FATAL(vm, !pnew);
  metapkt_free(vm->packets[hd0.pktnum], 1);
  vm->packets[hd0.pktnum] = pnew;
}


static void ni_pktcopy(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  int slot;
  struct metapkt *pkt, *pnew;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  S_POP(vm, slot);
  FATAL(vm, slot < 0 || slot >= NETVM_MAXPKTS);
  pnew = metapkt_copy(pkt);
  FATAL(vm, !pnew);
  metapkt_free(vm->packets[slot], 1);
  vm->packets[slot] = pnew;
}


static void ni_pktdel(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  metapkt_free(pkt, 1);
  vm->packets[pktnum] = NULL;
}


static void ni_hdrpush(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct metapkt *pkt;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[hd0.pktnum]));
  FATAL(vm, metapkt_pushhdr(pkt, hd0.htype) < 0);
}


static void ni_hdrpop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  metapkt_pophdr(pkt);
}


static void ni_hdrup(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  hdr = find_header(vm, &hd0);
  FATAL(vm, hdr == NULL);
  hdr_update(hdr);
}


static void ni_fixdlt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  metapkt_fixdlt(pkt);
}


static void ni_fixlen(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  /* TODO: allow more precise selection of which lengths to fix */
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  if ( pkt->layer[NETVM_HDI_XPORT] )
    FATAL(vm, hdr_fix_len(pkt->layer[NETVM_HDI_XPORT]) < 0);
  if ( pkt->layer[NETVM_HDI_NET] )
    FATAL(vm, hdr_fix_len(pkt->layer[NETVM_HDI_NET]) < 0);
  if ( pkt->layer[NETVM_HDI_LINK] )
    FATAL(vm, hdr_fix_len(pkt->layer[NETVM_HDI_LINK]) < 0);
}


static void ni_fixcksum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct metapkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  /* TODO: allow more precise selection of which checksums to fix */
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  if ( pkt->layer[NETVM_HDI_XPORT] )
    FATAL(vm, hdr_fix_cksum(pkt->layer[NETVM_HDI_XPORT]) < 0);
  if ( pkt->layer[NETVM_HDI_NET] )
    FATAL(vm, hdr_fix_cksum(pkt->layer[NETVM_HDI_NET]) < 0);
  if ( pkt->layer[NETVM_HDI_LINK] )
    FATAL(vm, hdr_fix_cksum(pkt->layer[NETVM_HDI_LINK]) < 0);
}


static void ni_hdrins(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct metapkt *pkt;
  uint32_t len;
  int moveup;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  moveup = inst->flags & NETVM_IF_MOVEUP;
  FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[hd0.pktnum]));
  S_POP(vm, len);
  FATAL(vm, hdr_insert(pkt->headers, hd0.offset, len, moveup) < 0);
}


static void ni_hdrcut(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct metapkt *pkt;
  uint32_t len;
  int moveup;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  moveup = inst->flags & NETVM_IF_MOVEUP;
  FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[hd0.pktnum]));
  S_POP(vm, len);
  FATAL(vm, hdr_cut(pkt->headers, hd0.offset, len, moveup) < 0);
}


static void ni_hdradj(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  uint32_t val;
  ptrdiff_t amt;
  int rv;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  hdr = find_header(vm, &hd0);
  FATAL(vm, hdr == NULL);
  S_POP(vm, val);
  amt = (int32_t)val;
  switch(hd0.field) {
  case NETVM_HDR_HOFF: rv = hdr_adj_hstart(hdr, amt); break;
  case NETVM_HDR_HLEN: rv = hdr_adj_hlen(hdr, amt); break;
  case NETVM_HDR_PLEN: rv = hdr_adj_plen(hdr, amt); break;
  case NETVM_HDR_TLEN: rv = hdr_adj_tlen(hdr, amt); break;
  default:
    VMERR(vm);
  }
  FATAL(vm, rv < 0);
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
  ni_ldpmeta, /* LDCLASS */
  ni_ldpmeta, /* LDTSSEC */
  ni_ldpmeta, /* LDTSNSEC */
  ni_ldhdrf,
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
  ni_hashdr,
  ni_unimplemented, /* PREX */
  ni_unimplemented, /* MREX */
  ni_halt,
  ni_branch, /* BR */
  ni_branch, /* BNZ */
  ni_branch, /* BZ */

  /* non-matching-only */
  ni_jump,
  ni_call,
  ni_return,
  ni_prnum, /* PRBIN */
  ni_prnum, /* PROCT */
  ni_prnum, /* PRDEC */
  ni_prnum, /* PRHEX */
  ni_prip,
  ni_preth,
  ni_pripv6,
  ni_prstr,
  ni_stpkt,
  ni_stpmeta, /* STCLASS */
  ni_stpmeta, /* STTSSEC */
  ni_stpmeta, /* STTSNSEC */
  ni_blkpmv, /* BULKP2M */
  ni_pktswap,
  ni_pktnew,
  ni_pktcopy,
  ni_pktdel,
  ni_hdrpush,
  ni_hdrpop,
  ni_hdrup,
  ni_fixdlt,
  ni_fixlen,
  ni_fixcksum,
  ni_hdrins,
  ni_hdrcut,
  ni_hdradj,
};


void netvm_init(struct netvm *vm, uint32_t *stack, uint32_t ssz,
                byte_t *mem, uint32_t memsz, struct emitter *outport)
{
  abort_unless(vm && stack && ssz > 0 );
  vm->stack = stack;
  vm->stksz = ssz;
  vm->mem = mem;
  vm->memsz = memsz;
  vm->rosegoff = memsz;
  if ( outport )
    vm->outport = outport;
  else
    vm->outport = &null_emitter;
  vm->inst = NULL;
  vm->ninst = 0;
  vm->pc = 0;
  vm->sp = 0;
  vm->matchonly = 0;
  memset(vm->packets, 0, sizeof(vm->packets));
}


int netvm_validate(struct netvm *vm)
{
  struct netvm_inst *inst;
  uint32_t i, maxi, newpc;

  if ( !vm || !vm->stack || (vm->rosegoff > vm->memsz) || !vm->inst ||
       (vm->ninst < 0) || (vm->ninst > MAXINST) )
    return -1;
  maxi = vm->matchonly ? NETVM_OC_MAX_MATCH : NETVM_OC_MAX;
  for ( i = 0; i < vm->ninst; i++ ) {
    inst = &vm->inst[i];
    if ( inst->opcode > maxi )
      return -1;
    if ( (inst->opcode == NETVM_OC_BR) || (inst->opcode == NETVM_OC_BNZ) ||
         (inst->opcode == NETVM_OC_BZ) ) {
      if ( IMMED(inst) ) {
        newpc = (uint32_t)inst->val + 1 + i;
        if ( newpc > vm->ninst )
          return -1;
        if ( vm->matchonly && (newpc <= i) )
          return -1;
      } else {
        if ( vm->matchonly )
          return -1;
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


void netvm_set_matchonly(struct netvm *vm, int matchonly)
{
  abort_unless(vm);
  vm->matchonly = matchonly;
}


void netvm_loadpkt(struct netvm *vm, struct pktbuf *p, int slot)
{
  struct metapkt *pkt;
  if ( (slot < 0) || (slot >= NETVM_MAXPKTS) )
    return;
  pkt = pktbuf_to_metapkt(p);
  abort_unless(pkt);
  metapkt_free(vm->packets[slot], 1);
  vm->packets[slot] = pkt;
}


struct pktbuf *netvm_clrpkt(struct netvm *vm, int slot, int keeppkb)
{
  struct metapkt *pkt;
  struct pktbuf *pkb = NULL;
  if ( (slot >= 0) && (slot < NETVM_MAXPKTS) && (pkt = vm->packets[slot]) ) {
    if ( keeppkb )
      pkb = pkt->pkb;
    metapkt_free(pkt, keeppkb);
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


/* reinitialize for running but with same packet and memory state */
void netvm_restart(struct netvm *vm)
{
  abort_unless(vm && vm->stack && vm->rosegoff <= vm->memsz && vm->inst && 
               vm->ninst >= 0 && vm->ninst <= MAXINST);
  vm->pc = 0;
  vm->sp = 0;
}


/* clear memory, set pc <= 0, discard packets */
void netvm_reset(struct netvm *vm)
{
  /* assume sanity checks in the called functions */
  netvm_clrmem(vm);
  netvm_clrpkts(vm);
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

