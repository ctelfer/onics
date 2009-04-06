#include "netvm.h"
#include <cat/emit_format.h>

#define FATAL(__cond, __vm) \
  if (__cond) { __vm->error = 1; __vm->running = 0; return; }

#define NONFATAL(__cond, __vm) \
  if (__cond) { __vm->error = 1; return; }

#define S_EMPTY(__vm)           (__vm->sp == 0)
#define S_HAS(__vm, __n)        (__vm->sp >= n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)

#define S_TOP(__vm, __v)                                                \
  do {                                                                  \
    FATAL(S_EMPTY(__vm));                                               \
    __v = __vm->stack[__vm->sp];                                        \
  } while (0)

#define S_POP(__vm, __v)                                                \
  do {                                                                  \
    FATAL(S_EMPTY(__vm));                                               \
    __v = __vm->stack[--__vm->sp];                                      \
  } while (0)

#define S_PUSH(__vm, __v)                                               \
  do {                                                                  \
    FATAL(S_FULL(__vm));                                                \
    __vm->stack[__vm->sp++] = (__v);                                    \
  } while (0)

#define CKWIDTH(__w) FATAL(!__w || (__w & (__w - 1)) || (__w > 8))


/* 
 * find header based on packet number, header type, and index.  So (3,8,1) 
 * means find the 2nd (0-based counting) TCP (PPT_TCP == 8) header in the 4th
 * packet.
 */
static struct hdr_parse *find_header(struct netvm *vm, struct netvm_hdr_desc *hd)
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


static void unimplemented(struct netvm *vm)
{
  struct netvm_instr *inst = &vm->inst[vm->pc];
  if ( vm->outport )
    emit_format(vm->outport, "Instruction %d not implemented\n", inst->opcode);
  vm->error = 1;
  vm->running = 0;
}


static void ni_pop(struct netvm *vm)
{
  uint64_t v;
  S_POP(vm, v);
}


static void ni_push(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  S_PUSH(vm, inst->u.num.val);
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
  register unsigned int width = inst->u.num.width;
  register unsigned int addr;
  CKWIDTH(width);
  if ( inst->u.num.immed ) {
    addr = inst->u.num.val;
  } else {
    S_POP(vm, val);
    addr = val;
  }
  FATAL(addr > vm->memsz || addr + width > vm->memsz);
  if ( inst->u.num.issigned )
    width = -width;
  switch(width) {
  case -1: val = (int64_t)*(int8_t *)(vm->mem + addr) = val; break;
  case -2: val = (int64_t)*(int16_t *)(vm->mem + addr) = val; break;
  case -4: val = (int64_t)*(int32_t *)(vm->mem + addr) = val; break;
  case -8: val = (int64_t)*(int64_t *)(vm->mem + addr) = val; break;
  case 1: val = *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: val = *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: val = *(uint32_t *)(vm->mem + addr) = val; break;
  case 8: val = *(uint64_t *)(vm->mem + addr) = val; break;
  default:
    FATAL(0);
  }
  S_PUSH(vm, val);
}


static void ni_stmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t val;
  register unsigned int addr = inst->u.num.val;
  register int width = inst->u.num.width;
  CKWIDTH(width);
  if ( inst->u.num.immed ) {
    addr = inst->u.num.val;
  } else {
    S_POP(vm, val);
    addr = val;
  }
  FATAL(addr > vm->memsz || addr + width > vm->memsz);
  S_POP(vm, val);
  switch(width) {
  case 1: *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: *(uint32_t *)(vm->mem + addr) = val; break;
  case 8: *(uint64_t *)(vm->mem + addr) = val; break;
  default:
    FATAL(0);
  }
}


static void ni_ldpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  uint64_t val;
  uint32_t addr;
  int width;

  hd0 = inst->hdr;
  if ( hd0.flags & NETVM_HDF_HDONSTACK ) {
    S_POP(vm, val);
    hd0.pktnum = val & 0xFF;
    hd0.htype = (val >> 8) & 0xFF;
    hd0.idx = (val >> 16) & 0xFF;
    hd0.field = (val >> 24) & 0xFF;
  } 
  if ( hd0.flags & NETVM_HDF_OFFONSTACK ) {
    S_POP(vm, val);
    hd0.offset = val;
  }
  width = hd0.width;
  CKWIDTH(width);

  FATAL((hd0.offset + width < hd0.offset) || !NETVM_ISHDROFF(hd0.field));
  hdr = find_header(vm, &hd0);
  FATAL(hdr == NULL);

  switch(hd0.field) {
  case NETVM_HDR_HOFF:
    FATAL(hd0.offset + width >= hdr_hlen(hdr));
    addr = hdr->hoff + hd0.offset;
    break;
  case NETVM_HDR_POFF:
    FATAL(hd0.offset + width >= hdr_plen(hdr));
    addr = hdr->poff + hd0.offset;
    break;
  case NETVM_HDR_TOFF:
    FATAL(hd0.offset + width >= hdr_tlen(hdr));
    addr = hdr->toff + hd0.offset;
    break;
  case NETVM_HDR_EOFF:
  default:
    FATAL(0);
    break;
  }

  switch(width) {
  case 1: 
    val = (int64_t)*(int8_t *)(hdr->data + addr); 
    if ( hd0.flags & NETVM_HDF_IPHLEN ) { 
      val = (val & 0xf) << 2;
    } else if ( hd0.flags & NETVM_HDF_TCPHLEN ) {
      val = (val & 0xf0) >> 2;
    } else { 
      if ( hd0.issigned )
        val |= -(val & 0x80);
    }
    break;
  case 2: 
    val = *(uint16_t *)(hdr->data + addr); 
    if ( hdr0.flags & NETVM_HDRF_TOHOST ) {
      val = ntoh16(val);
    } else if ( hdr0.flags & NETVM_HDRF_TONET ) {
      val = hton16(val);
    }
    if ( hd0.issigned )
      val |= -(val & 0x8000);
    break;
  case 4: 
    val = *(uint32_t *)(hdr->data + addr); 
    if ( hdr0.flags & NETVM_HDRF_TOHOST ) {
      val = ntoh32(val);
    } else if ( hdr0.flags & NETVM_HDRF_TONET ) {
      val = hton32(val);
    }
    if ( hd0.issigned )
      val |= -(val & 0x80000000);
    break;
  case 8: 
    val = *(uint64_t *)(hdr->data + addr); 
    if ( hdr0.flags & NETVM_HDRF_TOHOST ) {
      val = ntoh64(val);
    } else if ( hdr0.flags & NETVM_HDRF_TONET ) {
      val = hton64(val);
    }
    break;
  default:
    FATAL(0);
  }
  S_PUSH(vm, val);
}


static void ni_ldpmeta(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  int pktnum = inst->u.hdr.pktnum;
  struct netvmpkt *pkt;
  FATAL((pktnum >= NETVM_MAXPKTS) || !(pkt = vm->packets[pktnum]));
  if ( inst->opcode == NETVM_IT_LDCLASS ) {
    S_PUSH(vm, pkt->packet->pkt_class);
  } else {
    abort_unless(inst->type == NETVM_IT_LDTS);
    S_PUSH(vm, pkt->packet->pkt_timestamp);
  }
}


static void ni_ldhdrf(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0;
  struct hdr_parse *hdr;
  uint64_t val;
  uint32_t addr;

  hd0 = inst->hdr;
  if ( hd0.flags & NETVM_HDF_HDONSTACK ) {
    S_POP(vm, val);
    hd0.pktnum = val & 0xFF;
    hd0.htype = (val >> 8) & 0xFF;
    hd0.idx = (val >> 16) & 0xFF;
    hd0.field = (val >> 24) & 0xFF;
  } 
  if ( hd0.flags & NETVM_HDF_OFFONSTACK ) {
    S_POP(vm, val);
    hd0.offset = val;
  }

  FATAL(!NETVM_HDRFLDOK(hd0.field));
  hdr = find_header(vm, &hd0);
  FATAL(hdr == NULL);

  switch (hd0.field) {
  NETVM_HDR_HOFF: S_PUSH(vm, hdr->hoff); break;
  NETVM_HDR_POFF: S_PUSH(vm, hdr->poff); break;
  NETVM_HDR_TOFF: S_PUSH(vm, hdr->toff); break;
  NETVM_HDR_EOFF: S_PUSH(vm, hdr->eoff); break;
  NETVM_HDR_HLEN: S_PUSH(vm, hdr_hlen(hdr)); break;
  NETVM_HDR_PLEN: S_PUSH(vm, hdr_plen(hdr)); break;
  NETVM_HDR_TLEN: S_PUSH(vm, hdr_tlen(hdr)); break;
  NETVM_HDR_LEN:  S_PUSH(vm, hdr_totlen(hdr)); break;
  default:
    abort_unless(0);
  }
}


static void ni_numop(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t out, v1, v2;
  int amt;
  if ( (inst->opcode < NETVM_IT_NOT) || (inst->opdcode > NETVM_IT_SIGNX)) {
    if ( inst->u.num.immed )  {
      v2 = inst->u.num.val;
    } else {
      S_POP(vm, v2);
    }
  }
  S_POP(vm, v1);
  switch (inst->opcode) {
  case NETVM_IT_NOT: out = ~v1; break;
  case NETVM_IT_TONET: 
    CKWIDTH(inst->u.num.width);
    switch (inst->u.num.width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    case 8: out = hton64(v1); break;
    }
    break;
  case NETVM_IT_TOHOST: 
    CKWIDTH(inst->u.num.width);
    switch (inst->u.num.width) {
    case 2: out = hton16(v1); break;
    case 4: out = hton32(v1); break;
    case 8: out = hton64(v1); break;
    }
    break;
  case NETVM_IT_SIGNX: 
    CKWIDTH(inst->u.num.width);
    case 1: out = v1 | -(v1 & 0x80); break;
    case 2: out = v1 | -(v1 & 0x8000); break;
    case 4: out = v1 | -(v1 & 0x80000000); break;
    break;
  case NETVM_IT_ADD: out = v1 + v2; break;
  case NETVM_IT_SUB: out = v1 - v2; break;
  case NETVM_IT_MUL: out = v1 * v2; break;
  case NETVM_IT_DIV: out = v1 / v2; break;
  case NETVM_IT_MOD: out = v1 % v2; break;
  case NETVM_IT_SHL: out = v1 << (v2 & 0x3F); break;
  case NETVM_IT_SHR: out = v1 >> (v2 & 0x3F); break;
  case NETVM_IT_SHRA:
    amt = v2 & 0x3F;
    out = (v1 >> amt) | ~(1 << (63 - amt));
    break;
  case NETVM_IT_AND: out = v1 & v2; break;
  case NETVM_IT_OR: out = v1 | v2; break;
  case NETVM_IT_EQ: out = v1 == v2; break;
  case NETVM_IT_NEQ: out = v1 != v2; break;
  case NETVM_IT_LT: out = v1 < v2; break;
  case NETVM_IT_LE: out = v1 <= v2; break;
  case NETVM_IT_GT: out = v1 > v2; break;
  case NETVM_IT_GE: out = v1 >= v2; break;
  case NETVM_IT_SLT: out = (int64_t)v1 < (int64_t)v2; break;
  case NETVM_IT_SLE: out = (int64_t)v1 <= (int64_t)v2; break;
  case NETVM_IT_SGT: out = (int64_t)v1 > (int64_t)v2; break;
  case NETVM_IT_SGE: out = (int64_t)v1 >= (int64_t)v2; break;
  default:
    abort_unless(0);
  }
  S_PUSH(vm, out);
}


static void ni_hashdr(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc hd0 = { 0, 0, 0, 0, inst->u.hdr.pktnum, 
                               inst->u.hdr.htype, 0, 0, 0};
  uint64_t val;
  val = find_header(vm, &hd0) != NULL;
  S_PUSH(vm, val);
}


static void ni_halt(struct netvm *vm)
{
  vm->running = 0;
}


static void ni_prnum(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  char fmtbuf[12];
  register int nwidth = inst->u.num.width;
  register int swidth = inst->u.num.val;
  uint64_t val;

  abort_unless(vm->outport);
  CKWIDTH(nwidth);
  FATAL(swidth > 64 || swidth < 0);

  switch (inst->opcode) {
  case NETVM_IT_PRBIN: 
    if ( swidth )
      sprintf(fmtbuf, "%%0%dllb", swidth);
    else
      sprintf(fmtbuf, "%%llb");
    break;
  case NETVM_IT_PROCT:
    if ( swidth )
      sprintf(fmtbuf, "%%0%dllo", swidth);
    else
      sprintf(fmtbuf, "%%llo");
    break;
  case NETVM_IT_PRDEC:
    if ( swidth ) {
      if ( inst->u.num.issigned )
        sprintf(fmtbuf, "%%0%dlld", swidth);
      else
        sprintf(fmtbuf, "%%0%dllu", swidth);
    } else { 
      if ( inst->u.num.issigned )
        sprintf(fmtbuf, "%%lld");
      else
        sprintf(fmtbuf, "%%llu");
    }
    break;
  case NETVM_IT_PRHEX:
    if ( swidth )
      sprintf(fmtbuf, "%%0%dllx", swidth);
    else
      sprintf(fmtbuf, "%%llx");
  default:
    abort_unless(0);
  }

  S_POP(vm, val);
  /* mask out all irrelevant bits */
  if ( nwidth < 8 )
    val &= ~((1 << (nwidth * 8)) - 1);
  /* sign extend the result if we are printing a signed decimal */
  if ( (inst->u.num.issigned) && (inst->opcode == NETVM_IT_PRDEC) )
    val |= -(val & (1 << (nwidth * 8 - 1)));
  emit_format(vm->outport, fmtbuf, val);
}


static void ni_prip(struct netvm *vm)
{
  uint32_t val;
  byte_t *bp = &val;
  abort_unless(vm->outport);
  S_POP(vm, val);
  /* Assumes network byte order */
  emit_format(vm->outport, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]);
}


struct netvm_inst g_netvm_ops[NTVM_IT_MAX+1] = { 
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

  /* non-matching-only */
  ni_prnum, /* PRBIN */
  ni_prnum, /* PROCT */
  ni_prnum, /* PRDEC */
  ni_prnum, /* PRHEX */
  ni_prip,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
};


void init_netvm(struct netvm *vm, struct netvm_data *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                struct emitter *outport)
{
  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
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
  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
  vm->pc = 0;
  vm->sp = 0;
  for ( i = 0; i < NETVM_MAXPACKETS; ++i )
    vm->packets[i] = NULL;
  memset(vm->mem, 0, vm->rosegoff);
  if ( inst != NULL ) {
    vm->inst = inst;
    vm->ninst = ni;
  }
}


/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err */
int run_netvm(struct netvm *vm, int maxcycles, int *rv)
{
  unsigned i, maxi;
  struct netvm_instr *inst;

  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
  if ( !vm->inst )
    return -1;

  if ( vm->matchonly )
    maxi = NTVM_IT_MAX_MATCH;
  else
    maxi =  NTVM_IT_MAX;
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
    else if ( vm->running && !vm->error )
      ++vm->pc;
    /* decrement cycle count if running for a limited duration */
    if ( maxcycles > 0 )
      --maxcycles;
  }

  if ( maxcycles == 0 )
    return -2;
  else if ( vm->error )
    return -1;
  if ( vm->sp == 0 )
    return 0;
  if ( rv )
    *rv = TOP(vm);
  return 1;
}

