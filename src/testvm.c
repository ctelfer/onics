#include <stdio.h>
#include <stdlib.h>
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
byte_t vm_memory[512];


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
  /*8*/{ NETVM_OC_LT, 0, NETVM_IF_IMMED, 10 },
  /*9*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED,  5 },
  /*10*/{ NETVM_OC_PUSH, 0, 0, 64 },
  /*11*/{ NETVM_OC_PRSTR, 0, NETVM_IF_IMMED, 1 },
  /*12*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /*13*/{ NETVM_OC_STMEM, 8, NETVM_IF_IMMED, 0 },
  /*14*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, (uint32_t)0 - 9 },
  /*15*/{ NETVM_OC_POP, 0, 0, 0 },
  /*16*/{ NETVM_OC_PUSH, 0, 0, 72 },
  /*17*/{ NETVM_OC_PRSTR, 0, NETVM_IF_IMMED, 1 },
};

struct netvm_program {
  struct netvm_inst *   code;
  unsigned              codelen;
  const char *          desc;
  int                   nopkts;
  int                   filter;
} vm_progs[] = { 
  { vm_prog_istcp, array_length(vm_prog_istcp), 
    "istcp -- Test if the packet has a TCP header", 0, 0 },
  { vm_prog_tcperr, array_length(vm_prog_tcperr),
    "tcperr -- Test if the packet is TCP and has errors", 0, 0 },
  { vm_prog_isudp, array_length(vm_prog_isudp), 
    "isudp -- Test if the packet is UDP", 0, 0 },
  { vm_prog_fixcksum, array_length(vm_prog_fixcksum),
    "fixcksum -- fix checksums on packets", 0, 1 },
  { vm_prog_toggledf, array_length(vm_prog_toggledf),
    "toggledf -- toggle the df bit in the IP header and fix checksums", 0, 1 },
  { vm_prog_count10, array_length(vm_prog_count10),
    "count10 -- print out 10 '.'s followed by a newline", 1, 0 }
};
unsigned prognum = 0;


void usage()
{
  char buf[4096];
  char pdesc[80];
  int i;
  optparse_print(&optparser, buf, sizeof(buf));
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


void run_without_packets(struct netvm *vm)
{
  int vmrv;
  uint64_t rc;
  vmrv = netvm_run(vm, -1, &rc);

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


void run_with_packets(struct netvm *vm, int filter)
{
  struct pktbuf *p;
  int npkt = 0;
  int npass = 0;
  int vmrv;
  uint64_t rc;

  while ( pkt_file_read(stdin, &p) > 0 ) {
    ++npkt;
    netvm_reset(vm);
    netvm_loadpkt(vm, p, 0);
    vmrv = netvm_run(vm, -1, &rc);

    if ( vmrv == 0 ) {
      fprintf(stderr, "Packet %u: no return value\n", npkt);
    } else if (vmrv == 1) {
      fprintf(stderr, "Packet %u: VM returned value %x\n", npkt, (unsigned)rc);
      if ( rc )
        ++npass;
    } else if (vmrv == -1) {
      fprintf(stderr, "Packet %u: VM returned error\n", npkt);
    } else if (vmrv == -2) {
      fprintf(stderr, "Packet %u: VM out of cycles\n", npkt);
    } else {
      abort_unless(0);
    }

    if ( filter ) {
      p = netvm_clrpkt(vm, 0, 1);
      if ( p ) {
        if ( pkt_file_write(stdout, p) < 0 )
          err("Error writing out packet %d\n", npkt);
        pkt_free(p);
      }
    }
  }
  netvm_reset(vm);

  fprintf(stderr, "%u out of %u packets passed\n", npass, npkt);
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
             array_length(vm_memory), array_length(vm_memory), 
             (prog->nopkts ? &fe.fe_emitter : NULL));
  if ( !prog->filter )
    vm.matchonly = 1;
  if ( netvm_setcode(&vm, prog->code, prog->codelen) < 0)
    err("Error validating program %d\n", prognum);

  if ( prog->nopkts ) {
    run_without_packets(&vm);
  } else {
    run_with_packets(&vm, prog->filter);
  }

  return 0;
}
