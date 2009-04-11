#include "config.h"
#include "netvm.h"
#include <string.h>
#include <stdlib.h>
#include <cat/emit_format.h>
#include <cat/emalloc.h>
#include "util.h"

#define IMMED(inst) ((inst)->flags & NETVM_IF_IMMED)
#define ISSIGNED(inst) ((inst)->flags & NETVM_IF_SIGNED)

#define VMERR(__vm) do { __vm->error = 1; return; } while (0)

#define FATAL(__vm, __cond) \
  if (__cond) { __vm->error = 1; return; }

#define S_EMPTY(__vm)           (__vm->sp == 0)
#define S_HAS(__vm, __n)        (__vm->sp >= n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)

#define S_TOP(__vm, __v)                                                \
  do {                                                                  \
    FATAL((__vm), S_EMPTY(__vm));                                       \
    __v = __vm->stack[__vm->sp-1];                                      \
  } while (0)

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

#define CKWIDTH(__vm, __w) FATAL((__vm), !__w || (__w & (__w - 1)) || (__w > 8))


typedef void (*netvm_op)(struct netvm *vm);


/* 
 * find header based on packet number, header type, and index.  So (3,8,1) 
 * means find the 2nd (0-based counting) TCP (PPT_TCP == 8) header in the 4th
 * packet.
 */
static struct hdr_parse *find_header(struct netvm *vm, 
                                     struct netvm_hdr_desc *hd)
{
  struct netvmpkt *pkt;
  struct hdr_parse *hdr;
  int n = 0;
  if ( hd->pktnum >= NETVM_MAXPKTS )
    return NULL;
  pkt = vm->packets[hd->pktnum];
  if ( !pkt )
    return NULL;
  abort_unless(pkt->packet && pkt->headers);
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


#if 0
static void unimplemented(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  if ( vm->outport )
    emit_format(vm->outport, "Instruction %d not implemented\n", inst->opcode);
  vm->error = 1;
}
#endif


static void ni_pop(struct netvm *vm)
{
  uint64_t v;
  S_POP(vm, v);
}


static void ni_push(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  S_PUSH(vm, inst->val);
}


static void ni_dup(struct netvm *vm)
{
  uint64_t val;
  S_TOP(vm, val);
  S_PUSH(vm, val);
}


static void ni_ldmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t val;
  register int width = inst->width;
  register uint32_t addr;
  FATAL(vm, !vm->mem || !vm->memsz);
  CKWIDTH(vm, width);
  if ( IMMED(inst) ) {
    addr = inst->val;
  } else {
    S_POP(vm, addr);
  }
  FATAL(vm, addr > vm->memsz || addr + width > vm->memsz);
  if ( ISSIGNED(inst) )
    width = -width;
  switch(width) {
  case -1: val = (int64_t)*(int8_t *)(vm->mem + addr); break;
  case -2: val = (int64_t)*(int16_t *)(vm->mem + addr); break;
  case -4: val = (int64_t)*(int32_t *)(vm->mem + addr); break;
  case -8: val = (int64_t)*(int64_t *)(vm->mem + addr); break;
  case 1: val = *(uint8_t *)(vm->mem + addr); break;
  case 2: val = *(uint16_t *)(vm->mem + addr); break;
  case 4: val = *(uint32_t *)(vm->mem + addr); break;
  case 8: val = *(uint64_t *)(vm->mem + addr); break;
  default:
    VMERR(vm);
  }
  S_PUSH(vm, val);
}


static void ni_stmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t val;
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
  case 8: *(uint64_t *)(vm->mem + addr) = val; break;
  default:
    VMERR(vm);
  }
}


static void get_hd(struct netvm *vm, struct netvm_inst *inst,
                   struct netvm_hdr_desc *hd)
{
  uint64_t val;
  if ( IMMED(inst) )
    val = inst->val;
  else
    S_POP(vm, val);
  hd->pktnum = (val >> 56) & 0xff;
  hd->htype = (val >> 48) & 0xff;
  hd->idx = (val >> 40) & 0xff;
  hd->field = (val >> 32) & 0xff;
  hd->offset = val & 0xffffffff;
}


static void get_hdr_info(struct netvm *vm, struct netvm_inst *inst, 
                         struct netvm_hdr_desc *hd, uint32_t *addr, 
                         struct hdr_parse **hdrp)
{
  int width;
  struct hdr_parse *hdr;

  get_hd(vm, inst, hd);
  if ( vm->error )
    return;
  width = inst->width;
  CKWIDTH(vm, width);

  FATAL(vm, (hd->offset + width < hd->offset) || !NETVM_ISHDROFF(hd->field));
  hdr = find_header(vm, hd);
  FATAL(vm, hdr == NULL);

  switch(hd->field) {
  case NETVM_HDR_HOFF:
    FATAL(vm, hd->offset + width >= hdr_hlen(hdr));
    *addr = hdr->hoff + hd->offset;
    break;
  case NETVM_HDR_POFF:
    FATAL(vm, hd->offset + width >= hdr_plen(hdr));
    *addr = hdr->poff + hd->offset;
    break;
  case NETVM_HDR_TOFF:
    FATAL(vm, hd->offset + width >= hdr_tlen(hdr));
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
  uint64_t val;

  get_hdr_info(vm, inst, &hd0, &addr, &hdr);
  if ( vm->error )
    return;

  switch(inst->width) {
  case 1: 
    val = (int64_t)*(int8_t *)(hdr->data + addr); 
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
  case 8: 
    val = *(uint64_t *)(hdr->data + addr); 
    if ( inst->flags & NETVM_IF_TOHOST )
      val = ntoh64(val);
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
  struct netvmpkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  if ( inst->opcode == NETVM_OC_LDCLASS ) {
    S_PUSH(vm, pkt->packet->pkt_class);
  } else {
    abort_unless(inst->opcode == NETVM_OC_LDTS);
    S_PUSH(vm, pkt->packet->pkt_timestamp);
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
  hdr = find_header(vm, &hd0);
  FATAL(vm, hdr == NULL);

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
  default:
    abort_unless(0);
  }
}


static void ni_numop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t out, v1, v2;
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
  case NETVM_OC_ISNZ: out = v1 != 0; break;
  case NETVM_OC_TONET: 
    CKWIDTH(vm, inst->width);
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    case 8: out = hton64(v1); break;
    }
    break;
  case NETVM_OC_TOHOST: 
    CKWIDTH(vm, inst->width);
    switch (inst->width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    case 8: out = hton64(v1); break;
    }
    break;
  case NETVM_OC_SIGNX: 
    CKWIDTH(vm, inst->width);
    case 1: out = v1 | -(v1 & 0x80); break;
    case 2: out = v1 | -(v1 & 0x8000); break;
    case 4: out = v1 | -(v1 & 0x80000000); break;
    break;
  case NETVM_OC_ADD: out = v1 + v2; break;
  case NETVM_OC_SUB: out = v1 - v2; break;
  case NETVM_OC_MUL: out = v1 * v2; break;
  case NETVM_OC_DIV: out = v1 / v2; break;
  case NETVM_OC_MOD: out = v1 % v2; break;
  case NETVM_OC_SHL: out = v1 << (v2 & 0x3F); break;
  case NETVM_OC_SHR: out = v1 >> (v2 & 0x3F); break;
  case NETVM_OC_SHRA:
    amt = v2 & 0x3F;
    out = (v1 >> amt) | ~(1 << (63 - amt));
    break;
  case NETVM_OC_AND: out = v1 & v2; break;
  case NETVM_OC_OR: out = v1 | v2; break;
  case NETVM_OC_EQ: out = v1 == v2; break;
  case NETVM_OC_NEQ: out = v1 != v2; break;
  case NETVM_OC_LT: out = v1 < v2; break;
  case NETVM_OC_LE: out = v1 <= v2; break;
  case NETVM_OC_GT: out = v1 > v2; break;
  case NETVM_OC_GE: out = v1 >= v2; break;
  case NETVM_OC_SLT: out = (int64_t)v1 < (int64_t)v2; break;
  case NETVM_OC_SLE: out = (int64_t)v1 <= (int64_t)v2; break;
  case NETVM_OC_SGT: out = (int64_t)v1 > (int64_t)v2; break;
  case NETVM_OC_SGE: out = (int64_t)v1 >= (int64_t)v2; break;
  default:
    abort_unless(0);
  }
  S_PUSH(vm, out);
}


static void ni_hashdr(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  uint64_t val;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  val = find_header(vm, &hd0) != NULL;
  S_PUSH(vm, val);
}


static void ni_halt(struct netvm *vm)
{
  vm->running = 0;
}


static void ni_branch(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint32_t addr;
  if ( IMMED(inst) )
    addr = inst->val;
  else
    S_POP(vm, addr);
  if ( inst->opcode == NETVM_OC_BRIF ) {
    uint64_t cond;
    S_POP(vm, cond);
    if ( !cond )
      return;
  }
  /* ok to overflow number of instructions by 1: implied halt instruction */
  FATAL(vm, addr > vm->ninst);
  vm->pc = addr;
  vm->branch = 1;
}


static void ni_prnum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  char fmtbuf[12];
  register int nwidth = inst->width;
  register int swidth = inst->val;
  uint64_t val;

  abort_unless(vm->outport);
  CKWIDTH(vm, nwidth);
  FATAL(vm, swidth > 64 || swidth < 0); /* to prevent overflow of fmtbuf */

  switch (inst->opcode) {
  case NETVM_OC_PRBIN: 
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT64"b", swidth);
    else
      sprintf(fmtbuf, "%%"FMT64"b");
    break;
  case NETVM_OC_PROCT:
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT64"o", swidth);
    else
      sprintf(fmtbuf, "%%"FMT64"o");
    break;
  case NETVM_OC_PRDEC:
    if ( swidth ) {
      if ( ISSIGNED(inst) )
        sprintf(fmtbuf, "%%0%d"FMT64"d", swidth);
      else
        sprintf(fmtbuf, "%%0%d"FMT64"u", swidth);
    } else { 
      if ( ISSIGNED(inst) )
        sprintf(fmtbuf, "%%"FMT64"d");
      else
        sprintf(fmtbuf, "%%"FMT64"u");
    }
    break;
  case NETVM_OC_PRHEX:
    if ( swidth )
      sprintf(fmtbuf, "%%0%d"FMT64"x", swidth);
    else
      sprintf(fmtbuf, "%%"FMT64"x");
  default:
    abort_unless(0);
  }

  S_POP(vm, val);
  /* mask out all irrelevant bits */
  if ( nwidth < 8 )
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
  uint64_t vhi, vlo;
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
  uint64_t val;

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
  case 8: {
    if ( inst->flags & NETVM_IF_TOHOST )
      val = hton64(val);
    *(uint64_t *)(hdr->data + addr) = val;
  } break;
  default:
    abort_unless(0); /* should be checked in get_hdr_info() */
  }
}


static void ni_stpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct netvmpkt *pkt;
  uint64_t val;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  S_POP(vm, val);
  if ( inst->opcode == NETVM_OC_STCLASS ) {
    pkt->packet->pkt_class = val;
  } else {
    abort_unless(inst->opcode == NETVM_OC_STTS);
    pkt->packet->pkt_timestamp = val;
  }
}


static void ni_newpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct netvmpkt *pnew;
  struct pktbuf *p;
  int slot;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  FATAL(vm, hd0.pktnum >= NETVM_MAXPKTS);
  FATAL(vm, pkt_create(&p, hd0.offset, hd0.htype) < 0);
  pnew = pktbuf_to_netvmpkt(p);
  if ( !pnew ) {
    pkt_free(p);
    VMERR(vm);
  }
  free_netvmpkt(release_netvm_packet(vm, hd0.pktnum));
  set_netvm_packet(vm, slot, pnew);
}


static void ni_pktcopy(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  int slot;
  struct netvmpkt *pkt, *pnew;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else {
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  S_POP(vm, slot);
  FATAL(vm, slot < 0 || slot >= NETVM_MAXPKTS);
  pnew = emalloc(sizeof(*pnew));
  if ( pkt_copy(pkt->packet, &pnew->packet) < 0 ) {
    free(pnew);
    VMERR(vm);
  }
  if ( !(pnew->headers = hdr_copy(pkt->headers, pnew->packet->pkt_buffer)) ) {
    pkt_free(pnew->packet);
    free(pnew);
    VMERR(vm);
  }
  free_netvmpkt(release_netvm_packet(vm, slot));
  set_netvm_packet(vm, slot, pnew);
}


static void ni_crehdr(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct netvmpkt *pkt;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  FATAL(vm, (hd0.pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[hd0.pktnum]));
  FATAL(vm, hdr_add(hd0.htype, hdr_parent(pkt->headers)) < 0);
}


static void ni_fixlen(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct netvmpkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  FATAL(vm, hdr_fix_len(pkt->headers) < 0);
}


static void ni_fixcksum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum;
  struct netvmpkt *pkt;
  if ( IMMED(inst) ) {
    pktnum = inst->val;
  } else { 
    S_POP(vm, pktnum);
  }
  FATAL(vm, (pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  FATAL(vm, hdr_fix_cksum(pkt->headers) < 0);
}


static void ni_hdrins(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct netvmpkt *pkt;
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
  struct netvmpkt *pkt;
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
  uint64_t val;
  ptrdiff_t amt;
  int rv;
  get_hd(vm, inst, &hd0);
  if ( vm->error )
    return;
  hdr = find_header(vm, &hd0);
  FATAL(vm, hdr == NULL);
  S_POP(vm, val);
  amt = (int64_t)val;
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
  ni_pop,
  ni_push,
  ni_dup,
  ni_ldmem,
  ni_stmem,
  ni_ldpkt,
  ni_ldpmeta, /* LDCLASS */
  ni_ldpmeta, /* LDTS */
  ni_ldhdrf,
  ni_numop, /* NOT */
  ni_numop, /* INVERT */
  ni_numop, /* ISNZ */
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
  ni_halt,
  ni_branch, /* BR */
  ni_branch, /* BRIF */

  /* non-matching-only */
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
  ni_stpmeta, /* STTS */
  ni_newpkt,
  ni_pktcopy,
  ni_crehdr,
  ni_fixlen,
  ni_fixcksum,
  ni_hdrins,
  ni_hdrcut,
  ni_hdradj,
};


void init_netvm(struct netvm *vm, uint64_t *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                struct emitter *outport)
{
  abort_unless(vm && stack && mem && roseg <= memsz);
  vm->stack = stack;
  vm->stksz = ssz;
  vm->mem = mem;
  vm->memsz = memsz;
  vm->rosegoff = roseg;
  if ( outport )
    vm->outport = outport;
  else
    vm->outport = &null_emitter;
  vm->inst = NULL;
  vm->ninst = 0;
  reset_netvm(vm, NULL, 0);
}


/* clear memory, set pc <= 0, discard packets */
void reset_netvm(struct netvm *vm, struct netvm_inst *inst, unsigned ni)
{
  int i;
  abort_unless(vm && vm->stack && vm->mem && vm->rosegoff <= vm->memsz);
  vm->pc = 0;
  vm->sp = 0;
  for ( i = 0; i < NETVM_MAXPKTS; ++i )
    vm->packets[i] = NULL;
  memset(vm->mem, 0, vm->rosegoff);
  if ( inst != NULL ) {
    vm->inst = inst;
    vm->ninst = ni;
  }
}


/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err */
int run_netvm(struct netvm *vm, int maxcycles, uint64_t *rv)
{
  unsigned i, maxi;
  struct netvm_inst *inst;

  abort_unless(vm && vm->stack && vm->mem && vm->rosegoff <= vm->memsz);
  if ( !vm->inst )
    return -1;

  if ( vm->matchonly )
    maxi = NETVM_OC_MAX_MATCH;
  else
    maxi =  NETVM_OC_MAX;
  for ( i = 0; i < vm->ninst; i++ )
    if ( vm->inst[i].opcode > maxi )
      return -1;

  vm->error = 0;
  vm->running = 1;
  vm->branch = 0;

  while ( vm->running && !vm->error && maxcycles != 0 ) {
    inst = &vm->inst[vm->pc];
    (*g_netvm_ops[inst->opcode])(vm);
    /* if we branched: don't adjust the PC, otherwise clear the branch flag */
    if ( vm->branch )
      vm->branch = 0;
    else 
      ++vm->pc;
    if ( vm->pc >= vm->ninst ) {
      vm->running = 0;
      if ( vm->pc != vm->ninst ) 
        vm->error = 1;
    }
    /* decrement cycle count if running for a limited duration */
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


static unsigned pktdlt_to_ppt(uint32_t dltype)
{
  switch(dltype) {
  case PKTDL_ETHERNET2:
    return PPT_ETHERNET;
  default:
    return PPT_NONE;
  }
}


struct netvmpkt *pktbuf_to_netvmpkt(struct pktbuf *pb)
{
  struct netvmpkt *pnew;
  if ( !pb )
    return NULL;
  pnew = emalloc(sizeof(*pnew));
  pnew->packet = pb;
  pnew->headers = hdr_parse_packet(pktdlt_to_ppt(pb->pkt_dltype),
		                   pb->pkt_buffer, pb->pkt_offset, pb->pkt_len,
				   pb->pkt_buflen);
  if ( !pnew->headers ) {
    pkt_free(pnew->packet);
    free(pnew);
    pnew = NULL;
  }
  return pnew;
}


void free_netvmpkt(struct netvmpkt *pkt)
{
  if ( pkt ) {
    hdr_free(pkt->headers, 1);
    pkt_free(pkt->packet);
    free(pkt);
  }
}


void set_netvm_packet(struct netvm *vm, int slot, struct netvmpkt *pkt)
{
  if ( !vm || slot < 0 || slot >= NETVM_MAXPKTS )
    return;
  vm->packets[slot]  = pkt;
}


struct netvmpkt *release_netvm_packet(struct netvm *vm, int slot)
{
  struct netvmpkt *pkt;
  if ( !vm || slot < 0 || slot >= NETVM_MAXPKTS )
    return NULL;
  pkt = vm->packets[slot];
  vm->packets[slot] = NULL;
  return pkt;
}

