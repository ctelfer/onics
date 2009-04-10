#include <stdio.h>
#include <cat/stdemit.h>
#include "packet.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "netvm.h"


uint64_t vm_stack[64];
byte_t vm_memory[512];
struct netvm_inst vm_prog[] = { 
  { NETVM_OC_HASHDR, 0, NETVM_IF_IMMED, NETVM_HDESC(0, PPT_TCP, 0, 0, 0) },
  { NETVM_OC_HALT, 0, 0, 0 },
};



int main(int argc, char *argv[])
{
  struct pktbuf *p;
  struct netvm vm;
  int npkt = 0;
  int ntcp = 0;
  int vmrv;
  uint64_t rc;
  struct netvmpkt *nvp;

  install_default_proto_parsers();
  init_netvm(&vm, vm_stack, array_length(vm_stack), vm_memory, 
             array_length(vm_memory), array_length(vm_memory), NULL);

  while ( pkt_file_read(stdin, &p) > 0 ) {
    ++npkt;
    if ( (nvp = pktbuf_to_netvmpkt(p)) == NULL ) {
      printf("Error parsing packet %d\n", npkt);
      pkt_free(p);
      continue;
    }

    reset_netvm(&vm, vm_prog, array_length(vm_prog));
    set_netvm_packet(&vm, 0, pktbuf_to_netvmpkt(p));
    vmrv = run_netvm(&vm, -1, &rc);

    if ( vmrv == 0 ) {
      printf("Packet %u: no return value\n", npkt);
    } else if (vmrv == 1) {
      printf("Packet %u: VM returned value %d\n", npkt, (int)rc);
      if ( rc )
        ++ntcp;
    } else if (vmrv == -1) {
      printf("Packet %u: VM returned error\n", npkt);
    } else if (vmrv == -2) {
      printf("Packet %u: VM out of cycles\n", npkt);
    } else {
      abort_unless(0);
    }

    free_netvmpkt(release_netvm_packet(&vm, 0));
  }

  printf("%u out of %u TCP packets\n", ntcp, npkt);

  return 0;
}
