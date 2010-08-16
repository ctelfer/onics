#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include "pktbuf.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"


struct clopt options[] = { 
  CLOPT_INIT(CLOPT_UINT, 'h', "--help", "print help and exit"),
  CLOPT_INIT(CLOPT_UINT, 'p', "--prog", "select program to run"),
};

struct clopt_parser optparser = CLOPTPARSER_INIT(options,array_length(options));


uint32_t vm_stack[64];
byte_t vm_memory[1024];
#define ROSEGOFF (sizeof(vm_memory)/2)


struct meminit {
  const byte_t *        init;
  uint32_t              len;
  uint32_t              off;
};


struct netvm_inst vm_prog_istcp[] = { 
  { NETVM_OC_HASPRP, 0, NETVM_IF_IMMED, NETVM_PDESC(PPT_TCP,0,0,0) },
  { NETVM_OC_HALT, 0, 0, 0 },
};


struct netvm_inst vm_prog_tcperr[] = { 
  /*0*/{ NETVM_OC_HASPRP, 0, NETVM_IF_IMMED, NETVM_PDESC(PPT_TCP,0,0,0) },
  /*1*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*2*/{ NETVM_OC_NOT, 0, 0, 0 },
  /*3*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, /* END */ 2 },
  /*4*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
         NETVM_PDESC(PPT_TCP,0,NETVM_PRP_ERR,0) },
  /*5*/{ NETVM_OC_TOBOOL, 0, 0, 0 },
};


struct netvm_inst vm_prog_isudp[] = { 
  { NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
    NETVM_PDESC(NETVM_PRP_LAYER, MPKT_LAYER_XPORT, NETVM_PRP_TYPE, 0) },
  { NETVM_OC_EQ, 0, NETVM_IF_IMMED, PPT_UDP },
};

struct netvm_inst vm_prog_fixcksum[] = { 
  { NETVM_OC_FIXCKSUM, 0, NETVM_IF_IMMED, 0 }
};

struct netvm_inst vm_prog_toggledf[] = { 
  /*0*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
         NETVM_PDESC(NETVM_PRP_LAYER, MPKT_LAYER_NET, NETVM_PRP_TYPE, 0) },
  /*1*/{ NETVM_OC_NEQ, 0, NETVM_IF_IMMED, PPT_IPV4 },
  /*2*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, 4 /* END of prog */ },
  /*3*/{ NETVM_OC_LDPKT, 2, NETVM_IF_IMMED | NETVM_IF_TOHOST, 
         /* 2 bytes starting 8 from IP hdr */
         NETVM_PDESC(PPT_IPV4, 0, NETVM_PRP_HOFF, 6) },
  /* toggle the DF bit */
  /*4*/{ NETVM_OC_XOR, 0, NETVM_IF_IMMED, IPH_DFMASK },
  /*5*/{ NETVM_OC_STPKT, 2, NETVM_IF_IMMED | NETVM_IF_TONET, 
         NETVM_PDESC(PPT_IPV4, 0, NETVM_PRP_HOFF, 6) },
  /*6*/{ NETVM_OC_FIXCKSUM, 0, NETVM_IF_IMMED, 0 }
};


struct netvm_inst vm_prog_count10[] = { 
  /*0*/{ NETVM_OC_PUSH, 0, 0, 0x2E }, 
  /*1*/{ NETVM_OC_STMEM, 1, NETVM_IF_IMMED, 64 },
  /*2*/{ NETVM_OC_PUSH, 0, 0, 0xA }, 
  /*3*/{ NETVM_OC_STMEM, 1, NETVM_IF_IMMED, 72 },
  /*4*/{ NETVM_OC_PUSH, 0, 0, 0x0 }, 
  /*5*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, 0 },
  /*6*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, 0 },
  /*7*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*8*/{ NETVM_OC_GE, 0, NETVM_IF_IMMED, 10 },
  /*9*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED,  NETVM_BRF(6) },
  /*10*/{ NETVM_OC_PUSH, 0, 0, 64 }, 
  /*11*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          1 },
  /*12*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /*13*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, 0 },
  /*14*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, NETVM_BRB(8) },
  /*15*/{ NETVM_OC_POP, 0, 0, 0 },
  /*16*/{ NETVM_OC_PUSH, 0, 0, 72 }, 
  /*17*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          1 },
};


char hws1[] = "Hello World\n";
#define HWS_OFFSET      (ROSEGOFF)
#define HWS_SIZE        (sizeof(hws1)-1)
struct meminit hwmi[] = {
  { (byte_t*)hws1, HWS_SIZE, HWS_OFFSET } 
};


struct netvm_inst vm_prog_helloworld[] = { 
  { NETVM_OC_PUSH, 0, 0, HWS_OFFSET }, 
  { NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
    NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), HWS_SIZE },
};


uint32_t fibX = 7;
#define FIB_I0_OFFSET      (ROSEGOFF)
#define FIB_I0_SIZE        sizeof(uint32_t)
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
  /* 0*/{ NETVM_OC_PUSH, 0, 0, FIB_I1_OFFSET}, 
  /* 1*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          FIB_I1_SIZE },
  /* 2*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, FIB_I0_OFFSET },
  /* 3*/{ NETVM_OC_DUP, 0, 0, 0 },
  /* 4*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRDEC),
          NETVM_OPNUMV(0, 4) },
  /* 5*/{ NETVM_OC_PUSH, 0, 0, FIB_I2_OFFSET}, 
  /* 6*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          FIB_I2_SIZE },
  /* 7*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(13) },
  /* 8*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /* 9*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRDEC), 
          NETVM_OPNUMV(0, 4) },
  /*10*/{ NETVM_OC_PUSH, 0, 0, FIB_I3_OFFSET}, 
  /*11*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          FIB_I3_SIZE },
  /*12*/{ NETVM_OC_HALT, 0, 0, 0 },

  /* (v) <- Fib(n) */
  /*13*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*14*/{ NETVM_OC_GT, 0, NETVM_IF_IMMED, 2 },
  /*15*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(4) },
  /*16*/{ NETVM_OC_POP, 0, 0, 0 },
  /*17*/{ NETVM_OC_PUSH, 0, NETVM_IF_IMMED, 1 },
  /*18*/{ NETVM_OC_RETURN, 0, NETVM_IF_IMMED, 1 },
  /*19*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*20*/{ NETVM_OC_SUB, 0, NETVM_IF_IMMED, 1 },
  /*21*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(13) },
  /*22*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /*23*/{ NETVM_OC_SWAP, 0, 0, 1},
  /*24*/{ NETVM_OC_SUB, 0, NETVM_IF_IMMED, 2 },
  /*25*/{ NETVM_OC_PUSH, 0, 0, NETVM_JA(13), },
  /*26*/{ NETVM_OC_CALL, 0, NETVM_IF_IMMED, 1 },
  /*27*/{ NETVM_OC_ADD, 0, 0, 0 },
  /*28*/{ NETVM_OC_RETURN, 0, NETVM_IF_IMMED, 1 },
};


#define DUP1ST_PNUM     0
struct netvm_inst vm_prog_dup1st[] = { 
  /* 0*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, DUP1ST_PNUM },
  /* 1*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /* 2*/{ NETVM_OC_DUP, 0, 0, 0 },
  /* 3*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, DUP1ST_PNUM },
  /* 4*/{ NETVM_OC_LE, 0, NETVM_IF_IMMED, 1 },
  /* 5*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(3) },
  /* 6*/{ NETVM_OC_PKTDEL, 0, NETVM_IF_IMMED, 0 },
  /* 7*/{ NETVM_OC_HALT, 0, 0, 0 },
  /* 8*/{ NETVM_OC_PUSH, 0, 0, 1 }, 
  /* 9*/{ NETVM_OC_PUSH, 0, 0, 0 }, 
  /*10*/{ NETVM_OC_PKTCOPY, 0, 0, 0 }
};


char bms1[] = "Hello World\n";
#define BMS1_OFFSET      (ROSEGOFF)
#define BMS1_SIZE        (sizeof(bms1)-1)
char bms2[] = "\n";
#define BMS2_OFFSET      (BMS1_OFFSET + BMS1_SIZE)
#define BMS2_SIZE        (sizeof(bms2)-1)
struct meminit bmi[] = {
  { (byte_t*)bms1, BMS1_SIZE, BMS1_OFFSET },
  { (byte_t*)bms2, BMS2_SIZE, BMS2_OFFSET },
};


struct netvm_inst vm_prog_bulkmove[] = { 
  /* only consider the 1st TCP packet with at least 16 bytes of payload */
  /* 0*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
          NETVM_PDESC(NETVM_PRP_LAYER, MPKT_LAYER_XPORT, NETVM_PRP_TYPE, 0) },
  /* 1*/{ NETVM_OC_NEQ, 0, NETVM_IF_IMMED, PPT_TCP},
  /* 2*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(10) },
  /* 3*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
          NETVM_PDESC(PPT_TCP, 0, NETVM_PRP_PLEN, 0) },
  /* 4*/{ NETVM_OC_LT, 0, NETVM_IF_IMMED, 16 },
  /* 5*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(7) },
  /* 6*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, DUP1ST_PNUM },
  /* 7*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /* 8*/{ NETVM_OC_DUP, 0, 0, 0 },
  /* 9*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, DUP1ST_PNUM },
  /*10*/{ NETVM_OC_LE, 0, NETVM_IF_IMMED, 1 },
  /*11*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(3) },
  /*12*/{ NETVM_OC_PKTDEL, 0, NETVM_IF_IMMED, 0 },
  /*13*/{ NETVM_OC_HALT, 0, 0, 0 },

  /* First print the first 16 bytes of the payload */
  /*14*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED,
          NETVM_PDESC(PPT_TCP, 0, NETVM_PRP_POFF, 0) },
  /*15*/{ NETVM_OC_PUSH, 0, 0, 0 },
  /*16*/{ NETVM_OC_PUSH, 0, 0, 16 },
  /*17*/{ NETVM_OC_BULKP2M, 0, NETVM_IF_IMMED, 0 },
  /*18*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, 0 },
  /*19*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRHEX), 
          NETVM_OPNUMV(0, 4) },
  /*20*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, 4 },
  /*21*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRHEX), 
          NETVM_OPNUMV(0, 4) },
  /*22*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, 8 },
  /*23*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRHEX), 
          NETVM_OPNUMV(0, 4) },
  /*24*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, 12 },
  /*25*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRHEX), 
          NETVM_OPNUMV(0, 4) },
  /*26*/{ NETVM_OC_PUSH, 0, 0, BMS2_OFFSET}, 
  /*27*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          BMS2_SIZE },

  /* Next put "hello world" into the beginning of the packet */
  /*28*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED,
          NETVM_PDESC(PPT_TCP, 0, NETVM_PRP_POFF, 0) },
  /*29*/{ NETVM_OC_PUSH, 0, 0, BMS1_OFFSET },
  /*30*/{ NETVM_OC_PUSH, 0, 0, BMS1_SIZE },
  /*31*/{ NETVM_OC_BULKM2P, 0, NETVM_IF_IMMED, 0 }
};


#define HD_IDX          (ROSEGOFF - 8)
#define HD_PKNADDR      (ROSEGOFF - 4)
char hds1[] = "Packet ";
#define HDS1_OFFSET     (ROSEGOFF)
#define HDS1_SIZE       (sizeof(hds1)-1)
char hds2[] = ": ";
#define HDS2_OFFSET     (HDS1_OFFSET + HDS1_SIZE)
#define HDS2_SIZE       (sizeof(hds2)-1)
char hds3[] = " bytes";
#define HDS3_OFFSET     (HDS2_OFFSET + HDS2_SIZE)
#define HDS3_SIZE       (sizeof(hds3)-1)
char hds4[] = "\n\n";
#define HDS4_OFFSET     (HDS3_OFFSET + HDS3_SIZE)
#define HDS4_SIZE       (sizeof(hds4)-1)
char hds5[] = "\n\t";
#define HDS5_OFFSET     (HDS4_OFFSET + HDS4_SIZE)
#define HDS5_SIZE       (sizeof(hds5)-1)
struct meminit hdi[] = {
  { (byte_t*)hds1, HDS1_SIZE, HDS1_OFFSET },
  { (byte_t*)hds2, HDS2_SIZE, HDS2_OFFSET },
  { (byte_t*)hds3, HDS3_SIZE, HDS3_OFFSET },
  { (byte_t*)hds4, HDS4_SIZE, HDS4_OFFSET },
  { (byte_t*)hds5, HDS5_SIZE, HDS5_OFFSET },
};

struct netvm_inst vm_prog_hexdump[] = { 
  /*00*/{ NETVM_OC_PUSH, 0, 0, HDS1_OFFSET }, 
  /*01*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          HDS1_SIZE },
  /*02*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, HD_PKNADDR },
  /*03*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /*04*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*05*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, HD_PKNADDR },
  /*06*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRDEC), 
          NETVM_OPNUMV(0, 4) },
  /*07*/{ NETVM_OC_PUSH, 0, 0, HDS2_OFFSET }, 
  /*08*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          HDS2_SIZE },
  /*09*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
          NETVM_PDESC(PPT_NONE, 0, NETVM_PRP_PLEN, 0) },
  /*10*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRDEC), 
          NETVM_OPNUMV(0, 4) },
  /*11*/{ NETVM_OC_PUSH, 0, 0, HDS3_OFFSET }, 
  /*12*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          HDS3_SIZE },
  /*13*/{ NETVM_OC_PUSH, 0, 0, 0 }, 
  /*14*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, HD_IDX }, 
  /*15*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, HD_IDX }, 
  /*16*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*17*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
          NETVM_PDESC(PPT_NONE, 0, NETVM_PRP_PLEN, 0) },
  /*18*/{ NETVM_OC_GE, 0, 0, 0 },
  /*19*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(13) },
  /*20*/{ NETVM_OC_DUP, 0, 0, 0 },
  /*21*/{ NETVM_OC_MOD, 0, NETVM_IF_IMMED, 16 },
  /*22*/{ NETVM_OC_BNZ, 0, NETVM_IF_IMMED, NETVM_BRF(3) },
  /*23*/{ NETVM_OC_PUSH, 0, 0, HDS5_OFFSET }, 
  /*24*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          HDS5_SIZE },
  /*25*/{ NETVM_OC_PUSH, 0, 0, 
          NETVM_FULL_PDESC(0, PPT_NONE, 0, NETVM_PRP_POFF) },
  /*26*/{ NETVM_OC_LDPKT, 1, 0, 0 },
  /*27*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRHEX), 
          NETVM_OPNUMV(2, 4) },
  /*28*/{ NETVM_OC_LDMEM, 4, NETVM_IF_IMMED, HD_IDX }, 
  /*29*/{ NETVM_OC_ADD, 0, NETVM_IF_IMMED, 1 },
  /*30*/{ NETVM_OC_STMEM, 4, NETVM_IF_IMMED, HD_IDX }, 
  /*31*/{ NETVM_OC_BR, 0, NETVM_IF_IMMED, NETVM_BRB(16) }, 
  /*32*/{ NETVM_OC_POP, 0, 0, 0 },
  /*33*/{ NETVM_OC_PUSH, 0, 0, HDS4_OFFSET }, 
  /*34*/{ NETVM_OC_CPOP, NETVM_CPI_OUTPORT, 
          NETVM_IF_IMMED|NETVM_IF_CPIMMED|NETVM_CPOP(NETVM_CPOC_PRSTR), 
          HDS4_SIZE },
  /*35*/{ NETVM_OC_PKTDEL, 0, NETVM_IF_IMMED, 0 },
};


char meqs1[] = "\x45\x00\x00\x34";
#define MEQ_VAL_OFFSET      (ROSEGOFF)
#define MEQ_VAL_SIZE        (sizeof(meqs1)-1)
char meqs2[] = "\xff\x00\xff\xff";
#define MEQ_MASK_OFFSET     (MEQ_VAL_OFFSET + MEQ_VAL_SIZE)
#define MEQ_MASK_SIZE       (sizeof(meqs2)-1)
struct meminit meqsi[] = {
  { (byte_t*)meqs1, MEQ_VAL_SIZE, MEQ_VAL_OFFSET },
  { (byte_t*)meqs2, MEQ_MASK_SIZE, MEQ_MASK_OFFSET },
};


struct netvm_inst vm_prog_maskeq[] = { 
  /*00*/{ NETVM_OC_LDPRPF, 0, NETVM_IF_IMMED, 
          NETVM_PDESC(NETVM_PRP_LAYER, MPKT_LAYER_NET, NETVM_PRP_HOFF, 0) },
  /*01*/{ NETVM_OC_PUSH, 0, 0, 0 },
  /*02*/{ NETVM_OC_PUSH, 0, 0, MEQ_VAL_SIZE },
  /*03*/{ NETVM_OC_BULKP2M, 0, NETVM_IF_IMMED, 0 },
  /*04*/{ NETVM_OC_PUSH, 0, 0, 0 },
  /*05*/{ NETVM_OC_PUSH, 0, 0, MEQ_VAL_OFFSET },
  /*06*/{ NETVM_OC_PUSH, 0, 0, MEQ_MASK_OFFSET },
  /*07*/{ NETVM_OC_MASKEQ, 0, NETVM_IF_IMMED, MEQ_MASK_SIZE },
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
  { vm_prog_bulkmove, array_length(vm_prog_bulkmove),
    "bulkmove -- Bulk move data into and out of the 1st 16-byte TCPpacket", 0, 
    1, bmi, array_length(bmi) },
  { vm_prog_hexdump, array_length(vm_prog_hexdump),
    "hexdump -- Hex dump the packets", 0, 1, hdi, array_length(hdi) },
  { vm_prog_maskeq, array_length(vm_prog_maskeq),
    "mask equality -- Compare with 45000034 hex", 0, 0, meqsi, 
    array_length(meqsi) },
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


void print_vmret(int vmrv, uint32_t rc)
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
  uint32_t rc;
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
  uint32_t rc;

  while ( pkb_file_read(stdin, &p) > 0 ) {
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
          if ( pkb_file_write(stdout, p) < 0 )
            err("Error writing out packet %d\n", npkt);
          pkb_free(p);
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
  struct netvm_std_coproc vmcps;
  struct netvm_program *prog;
  struct file_emitter fe;
  int rv;

  parse_options(argc, argv);
  install_default_proto_parsers();
  prog = &vm_progs[prognum];
  file_emitter_init(&fe, (prog->filter ? stderr : stdout));
  netvm_init(&vm, vm_stack, array_length(vm_stack), vm_memory, 
             array_length(vm_memory));
  netvm_setrooff(&vm, ROSEGOFF);
  if ( init_netvm_std_coproc(&vm, &vmcps) < 0 )
    errsys("Error initializing NetVM coprocessors");
  set_outport_emitter(&vmcps.outport, &fe.fe_emitter);

  if ( !prog->filter )
    vm.matchonly = 1;
  if ( (rv = netvm_setcode(&vm, prog->code, prog->codelen)) < 0)
    err("Error validating program %d: %s\n", prognum, netvm_estr(rv));

  if ( prog->nopkts ) {
    run_without_packets(&vm, prog->mi, prog->nmi);
  } else {
    run_with_packets(&vm, prog->filter, prog->mi, prog->nmi);
  }

  return 0;
}
