#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdemit.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include "pktbuf.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "netvm.h"


struct clopt options[] = { 
  CLOPT_INIT(CLOPT_UINT, 'h', "--help", "print help and exit"),
  CLOPT_INIT(CLOPT_UINT, 'p', "--prog", "select program to run"),
};

struct clopt_parser optparser = CLOPTPARSER_INIT(options,array_length(options));


uint64_t vm_stack[64];
byte_t vm_memory[1024];
#define ROSEGOFF (sizeof(vm_memory)/2)


struct meminit {
  const byte_t *        init;
  uint32_t              len;
  uint32_t              off;
};


struct netvm_inst vm_prog_istcp[] = { 
  { NETVM_OC_HASHDR, 0, NETVM_IF_IMMED, NETVM_HDESC(0,PPT_TCP,0,0,0) },
  { NETVM_OC_HALT, 0, 0, 0 },
};


struct netvm_inst vm_prog_tcperr[] = { 
  /*0*/{ NETVM_OC_HASHDR, 0, NETVM_IF_IMMED, NETVM_HDESC(0,PPT_TCP,0,0,0) },
  /*1*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*2*/{ NETVM_OC_NOT, 0, 0, 0 },
  /*3*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, /* END */ 2 },
  /*4*/{ NETVM_OC_LDHDRF, 0, NETVM_IF_IMMED, 
         NETVM_HDESC(0,PPT_TCP,0,NETVM_HDR_ERR,0) },
  /*5*/{ NETVM_OC_TOBOOL, 0, 0, 0 },
};


struct netvm_inst vm_prog_isudp[] = { 
  { NETVM_OC_LDHDRF, 0, NETVM_IF_IMMED, 
    NETVM_HDESC(0, NETVM_HDLAYER, NETVM_HDI_XPORT, NETVM_HDR_TYPE, 0) },
  { NETVM_OC_EQ, 0, NETVM_IF_IMMED, PPT_UDP },
};

struct netvm_inst vm_prog_fixcksum[] = { 
  { NETVM_OC_FIXCKSUM, 0, NETVM_IF_IMMED, 0 }
};

struct netvm_inst vm_prog_toggledf[] = { 
  /*0*/{ NETVM_OC_LDHDRF, 0, NETVM_IF_IMMED, 
         NETVM_HDESC(0, NETVM_HDLAYER, NETVM_HDI_NET, NETVM_HDR_TYPE, 0) },
  /*1*/{ NETVM_OC_NEQ, 0, NETVM_IF_IMMED, PPT_IPV4 },
  /*2*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, 4 /* END of prog */ },
  /*3*/{ NETVM_OC_LDPKT, 2, NETVM_IF_IMMED | NETVM_IF_TOHOST, 
         /* 2 bytes starting 8 from IP hdr */
         NETVM_HDESC(0, PPT_IPV4, 0, NETVM_HDR_HOFF, 6) },
  /* toggle the DF bit */
  /*4*/{ NETVM_OC_XOR, 0, NETVM_IF_IMMED, IPH_DFMASK },
  /*5*/{ NETVM_OC_STPKT, 2, NETVM_IF_IMMED | NETVM_IF_TONET, 
         NETVM_HDESC(0, PPT_IPV4, 0, NETVM_HDR_HOFF, 6) },
  /*6*/{ NETVM_OC_FIXCKSUM, 0, NETVM_IF_IMMED, 0 }
};


struct netvm_inst vm_prog_count10[] = { 
  /*0*/{ NETVM_OC_PUSH, 0, 0, 0x2E }, 
  /*1*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, 64 },
  /*2*/{ NETVM_OC_PUSH, 0, 0, 0xA }, 
  /*3*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, 72 },
  /*4*/{ NETVM_OC_PUSH, 0, 0, 0x0 }, 
  /*5*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, 0 },
  /*6*/{ NETVM_OC_LDMEM, 8, NETVM_IF_IMMED, 0 },
  /*7*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*8*/{ NETVM_OC_GE, 0, NETVM_IF_IMMED, 10 },
  /*9*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED,  4 },
  /*10*/{ NETVM_OC_PRSTR, 1, NETVM_IF_IMMED, 64 },
  /*11*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /*12*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, 0 },
  /*13*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, (uint64_t)0 - 8 },
  /*14*/{ NETVM_OC_POP, 0, 0, 0 },
  /*15*/{ NETVM_OC_PRSTR, 1, NETVM_IF_IMMED, 72 },
};


char hws1[] = "Hello World\n";
#define HWS_OFFSET      (ROSEGOFF)
#define HWS_SIZE        (sizeof(hws1)-1)
struct meminit hwmi[] = {
  { (byte_t*)hws1, HWS_SIZE, HWS_OFFSET } 
};


struct netvm_inst vm_prog_helloworld[] = { 
  { NETVM_OC_PRSTR, HWS_SIZE, NETVM_IF_IMMED, HWS_OFFSET },
};


uint64_t fibX = 7;
#define FIB_I0_OFFSET      (ROSEGOFF)
#define FIB_I0_SIZE        sizeof(uint64_t)
const char fibs1[] = "Fibonnaci number ";
#define FIB_I1_OFFSET      (FIB_I0_OFFSET + FIB_I0_SIZE)
#define FIB_I1_SIZE        (sizeof(fibs1)-1)
const char fibs2[] = " is ";
#define FIB_I2_OFFSET      (FIB_I1_OFFSET + FIB_I1_SIZE)
#define FIB_I2_SIZE        (sizeof(fibs2)-1)
const char fibs3[] = "\n";
#define FIB_I3_OFFSET      (FIB_I2_OFFSET + FIB_I2_SIZE)
#define FIB_I3_SIZE        (sizeof(fibs3)-1)
struct meminit fibi[] = {
  { (byte_t*)&fibX, FIB_I0_SIZE, FIB_I0_OFFSET },
  { (byte_t*)fibs1, FIB_I1_SIZE, FIB_I1_OFFSET },
  { (byte_t*)fibs2, FIB_I2_SIZE, FIB_I2_OFFSET },
  { (byte_t*)fibs3, FIB_I3_SIZE, FIB_I3_OFFSET }
};

struct netvm_inst vm_prog_fib[] = { 
  /* 0*/{ NETVM_OC_PRSTR, FIB_I1_SIZE, NETVM_IF_IMMED, FIB_I1_OFFSET },
  /* 1*/{ NETVM_OC_LDMEM, 8, NETVM_IF_IMMED, FIB_I0_OFFSET },
  /* 2*/{ NETVM_OC_DUP, 0, 0, 0 },
  /* 3*/{ NETVM_OC_PRDEC, 8, 0, 0 },
  /* 4*/{ NETVM_OC_PRSTR, FIB_I2_SIZE, NETVM_IF_IMMED, FIB_I2_OFFSET },
  /* 5*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(10) },
  /* 6*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /* 7*/{ NETVM_OC_PRDEC, 8, 0, 0 },
  /* 8*/{ NETVM_OC_PRSTR, FIB_I3_SIZE, NETVM_IF_IMMED, FIB_I3_OFFSET },
  /* 9*/{ NETVM_OC_HALT, 0, 0, 0 },

  /* (v) <- Fib(n) */
  /*10*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*11*/{ NETVM_OC_GT, 0, NETVM_IF_IMMED, 2 },
  /*12*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(4) },
  /*13*/{ NETVM_OC_POP, 0, 0, 0 },
  /*14*/{ NETVM_OC_PUSH, 0, NETVM_IF_IMMED, 1 },
  /*15*/{ NETVM_OC_RETURN, 0, NETVM_IF_IMMED, 1 },
  /*16*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*17*/{ NETVM_OC_SUB, 0, NETVM_IF_IMMED, 1 },
  /*18*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(10) },
  /*19*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /*20*/{ NETVM_OC_SWAP, 0, 0, 1},
  /*21*/{ NETVM_OC_SUB, 0, NETVM_IF_IMMED, 2 },
  /*22*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(10), },
  /*23*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /*24*/{ NETVM_OC_ADD, 0, 0, 0 },
  /*25*/{ NETVM_OC_RETURN, 0, NETVM_IF_IMMED, 1 },
};


#define DUP1ST_PNUM     0
struct netvm_inst vm_prog_dup1st[] = { 
  /* 0*/{ NETVM_OC_LDMEM, 8, NETVM_IF_IMMED, DUP1ST_PNUM },
  /* 1*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /* 2*/{ NETVM_OC_DUP, 0, NETVM_IF_IMMED, 1 },
  /* 3*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, DUP1ST_PNUM },
  /* 4*/{ NETVM_OC_LE, 0, NETVM_IF_IMMED, 1 },
  /* 5*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, NETVM_BRF(3) },
  /* 6*/{ NETVM_OC_PKTDEL, 0, NETVM_IF_IMMED, 0 },
  /* 7*/{ NETVM_OC_HALT, 0, 0, 0 },
  /* 8*/{ NETVM_OC_PUSH, 0, 0, 1 }, 
  /* 9*/{ NETVM_OC_PUSH, 0, 0, 0 }, 
  /*10*/{ NETVM_OC_PKTCOPY, 0, 0, 0 }
};


struct netvm_program {
  struct netvm_inst *   code;
  unsigned              codelen;
  const char *          desc;
  int                   nopkts;
  int                   filter;
  struct meminit *      mi;
  int                   nmi;
} vm_progs[] = { 
  { vm_prog_istcp, array_length(vm_prog_istcp), 
    "istcp -- Test if the packet has a TCP header", 0, 0, NULL, 0 },
  { vm_prog_tcperr, array_length(vm_prog_tcperr),
    "tcperr -- Test if the packet is TCP and has errors", 0, 0, NULL, 0 },
  { vm_prog_isudp, array_length(vm_prog_isudp), 
    "isudp -- Test if the packet is UDP", 0, 0, NULL, 0 },
  { vm_prog_fixcksum, array_length(vm_prog_fixcksum),
    "fixcksum -- fix checksums on packets", 0, 1, NULL, 0 },
  { vm_prog_toggledf, array_length(vm_prog_toggledf),
    "toggledf -- toggle the df bit in the IP header and fix checksums", 0, 1, 
    NULL, 0 },
  { vm_prog_count10, array_length(vm_prog_count10),
    "count10 -- print out 10 '.'s followed by a newline", 1, 1, NULL, 0 },
  { vm_prog_helloworld, array_length(vm_prog_helloworld),
    "hello-world -- print out 'hello world' from a preinitialized string", 1, 1,
    hwmi, array_length(hwmi) },
  { vm_prog_fib, array_length(vm_prog_fib),
    "fib -- compute Xth fibonacci number", 1, 1, fibi, array_length(fibi) },
  { vm_prog_dup1st, array_length(vm_prog_dup1st),
    "dup1st -- duplicate the first packet and discard rest", 0, 1, NULL, 0 },
};
unsigned prognum = 0;


void usage()
{
  char buf[4096];
  char pdesc[128];
  int i;
  fprintf(stderr, "usage: testvm [options]\n");
  optparse_print(&optparser, buf, sizeof(buf));
  str_cat(buf, "\n", sizeof(buf));
  for ( i = 0; i < array_length(vm_progs); ++i ) {
    str_fmt(pdesc, sizeof(pdesc), "Program %2u: %s\n", i, vm_progs[i].desc);
    str_cat(buf, pdesc, sizeof(buf));
  }
  fprintf(stderr, "%s\n", buf);
  exit(1);
}


void parse_options(int argc, char *argv[])
{
  struct clopt *opt;
  int rv;
  optparse_reset(&optparser, argc, argv);
  while ( !(rv = optparse_next(&optparser, &opt)) ) {
    if ( opt->ch == 'p' ) {
      if ( opt->val.uint_val >= array_length(vm_progs) )
        usage();
      prognum = opt->val.uint_val;
    }
  }
  if ( rv < argc )
    usage();
}


void init_memory(struct netvm *vm, struct meminit *mi, size_t nmi)
{
  while (nmi > 0) {
    abort_unless(mi->off < vm->memsz && mi->off + mi->len < vm->memsz && 
                 mi->off + mi->len >= mi->off);
    memcpy(vm->mem + mi->off, mi->init, mi->len);
    ++mi;
    --nmi;
  }
}


void print_vmret(int vmrv, uint64_t rc)
{
  if ( vmrv == 0 ) {
    fprintf(stderr, "VM provided no return value\n");
  } else if (vmrv == 1) {
    fprintf(stderr, "VM returned value %x\n", (unsigned)rc);
  } else if (vmrv == -1) {
    fprintf(stderr, "VM returned error\n");
  } else if (vmrv == -2) {
    fprintf(stderr, "VM out of cycles\n");
  } else {
    abort_unless(0);
  }
}


void run_without_packets(struct netvm *vm, struct meminit *mi, size_t nmi)
{
  int vmrv;
  uint64_t rc;
  init_memory(vm, mi, nmi);
  vmrv = netvm_run(vm, -1, &rc);
  print_vmret(vmrv, rc);
}


void run_with_packets(struct netvm *vm, int filter, struct meminit *mi, 
                      size_t nmi)
{
  struct pktbuf *p;
  int npkt = 0;
  int npass = 0;
  int vmrv;
  int i;
  uint64_t rc;

  while ( pkt_file_read(stdin, &p) > 0 ) {
    ++npkt;
    netvm_restart(vm);
    netvm_loadpkt(vm, p, 0);
    init_memory(vm, mi, nmi);
    vmrv = netvm_run(vm, -1, &rc);

    if ( (vmrv == 1) && rc )
      ++npass;
    fprintf(stderr, "Packet %u: ", npkt);
    print_vmret(vmrv, rc);

    if ( filter && vmrv >= 0 ) {
      for ( i = 0; i < NETVM_MAXPKTS; ++i ) {
        p = netvm_clrpkt(vm, i, 1);
        if ( p ) {
          if ( pkt_file_write(stdout, p) < 0 )
            err("Error writing out packet %d\n", npkt);
          pkt_free(p);
        } 
      }
    }
  }
  netvm_reset(vm);

  fprintf(stderr, "%u out of %u packets returned 'true'\n", npass, npkt);
}


int main(int argc, char *argv[])
{
  struct netvm vm;
  struct netvm_program *prog;
  struct file_emitter fe;

  parse_options(argc, argv);
  install_default_proto_parsers();
  prog = &vm_progs[prognum];
  file_emitter_init(&fe, stdout);
  netvm_init(&vm, vm_stack, array_length(vm_stack), vm_memory, 
             array_length(vm_memory), ROSEGOFF, &fe.fe_emitter);
  if ( !prog->filter )
    vm.matchonly = 1;
  if ( netvm_setcode(&vm, prog->code, prog->codelen) < 0)
    err("Error validating program %d\n", prognum);

  if ( prog->nopkts ) {
    run_without_packets(&vm, prog->mi, prog->nmi);
  } else {
    run_with_packets(&vm, prog->filter, prog->mi, prog->nmi);
  }

  return 0;
}
