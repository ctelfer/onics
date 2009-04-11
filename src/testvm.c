#include <stdio.h>
#include <cat/err.h>
#include <cat/stdemit.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include "packet.h"
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
  /*3*/{ NETVM_OC_BRIF, 0, NETVM_IF_IMMED, /* END */ 6 },
  /*4*/{ NETVM_OC_LDHDRF, 0, NETVM_IF_IMMED, 
         NETVM_HDESC(0,PPT_TCP,0,NETVM_HDR_ERR,0) },
  /*5*/{ NETVM_OC_ISNZ, 0, 0, 0 },
};


struct netvm_programs {
  struct netvm_inst *   prog;
  unsigned              proglen;
  const char *          desc;
} vm_progs[] = { 
  { vm_prog_istcp, array_length(vm_prog_istcp), 
    "istcp -- Test if the packet has a TCP header" },
  { vm_prog_tcperr, array_length(vm_prog_tcperr),
    "tcperr -- Test if the packet is TCP and has errors" },
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
  err(buf);
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


int main(int argc, char *argv[])
{
  struct pktbuf *p;
  struct netvm vm;
  int npkt = 0;
  int npass = 0;
  int vmrv;
  uint64_t rc;

  parse_options(argc, argv);
  install_default_proto_parsers();
  netvm_init(&vm, vm_stack, array_length(vm_stack), vm_memory, 
             array_length(vm_memory), array_length(vm_memory), NULL);
  if ( netvm_setcode(&vm,vm_progs[prognum].prog,vm_progs[prognum].proglen) < 0)
    err("Error validating program %d", prognum);

  while ( pkt_file_read(stdin, &p) > 0 ) {
    ++npkt;
    netvm_reset(&vm);
    netvm_loadpkt(&vm, p, 0);
    vmrv = netvm_run(&vm, -1, &rc);

    if ( vmrv == 0 ) {
      printf("Packet %u: no return value\n", npkt);
    } else if (vmrv == 1) {
      printf("Packet %u: VM returned value %x\n", npkt, (unsigned)rc);
      if ( rc )
        ++npass;
    } else if (vmrv == -1) {
      printf("Packet %u: VM returned error\n", npkt);
    } else if (vmrv == -2) {
      printf("Packet %u: VM out of cycles\n", npkt);
    } else {
      abort_unless(0);
    }
  }
  netvm_reset(&vm);

  printf("%u out of %u packets passed\n", npass, npkt);

  return 0;
}
