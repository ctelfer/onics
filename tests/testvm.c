/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * testvm.c -- Test the NetVM with some basic programs.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include "prid.h"
#include "pktbuf.h"
#include "protoparse.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"


struct clopt options[] = {
	CLOPT_INIT(CLOPT_UINT, 'h', "--help", "print help and exit"),
	CLOPT_INIT(CLOPT_UINT, 'p', "--prog", "select program to run"),
};

struct clopt_parser optparser =
CLOPTPARSER_INIT(options, array_length(options));


uint64_t vm_stack[64];
byte_t vm_memory[2][1024];
#define RWSEG 0
#define ROSEG 1


struct meminit {
	const byte_t *init;
	uint32_t len;
	int seg;
	uint32_t off;
};


struct netvm_inst vm_prog_istcp[] = {
	NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_PIDX, 0),
};


struct netvm_inst vm_prog_tcperr[] = {
	/*0 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_PIDX, 0),
	/*1 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/*2 */ NETVM_BRIFNOT_F(3),
	/*3 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_ERR, 0),
	/*4 */ NETVM_OP(TOBOOL, 0, 0, 0, 0),
};


struct netvm_inst vm_prog_isudp[] = {
	NETVM_PDIOP(LDPFI, 0, 0, PRID_PCLASS_XPORT, 0, NETVM_PRP_PRID, 0),
	NETVM_OP(PUSH, 0, 0, 0, PRID_UDP),
	NETVM_OP(EQ, 0, 0, 0, 0),
};

struct netvm_inst vm_prog_fixcksum[] = {
	NETVM_PDIOP(PKFXCI, 0, 0, PRID_NONE, 0, 0, 0),
};

struct netvm_inst vm_prog_toggledf[] = {
	/*0 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_PCLASS_NET, 0, NETVM_PRP_PRID, 0),
	/*1 */ NETVM_OP(NEQI, 0, 0, 0, PRID_IPV4),
	/*2 */ NETVM_BRIF_F(5), /* end of the program */
	/* 2 bytes starting 6 bytes from start of first IP hdr of packet 0 */
	/*3 */ NETVM_PDIOP(LDPDI, 2, 0, PRID_IPV4, 0, NETVM_PRP_SOFF, 6),
	/* toggle the DF bit */
	/*4 */ NETVM_OP(XORI, 0, 0, 0, IPH_DFMASK),
	/*5 */ NETVM_PDIOP(STPDI, 2, 0, PRID_IPV4, 0, NETVM_PRP_SOFF, 6),
	/*6 */ NETVM_PDIOP(PKFXCI, 0, 0, PRID_IPV4, 0, 0, 0),
};


struct netvm_inst vm_prog_count10[] = {
	/*0 */ NETVM_OP(PUSH, 0, 0, 0, '.'), 
	/*1 */ NETVM_OP(STI, 1, RWSEG, 0, 64),
	/*2 */ NETVM_OP(PUSH, 0, 0, 0, '\n'), 
	/*3 */ NETVM_OP(STI, 1, RWSEG, 0, 72),
	/*4 */ NETVM_OP(PUSH, 0, 0, 0, 0), 
	/*5 */ NETVM_OP(STI, 4, RWSEG, 0, 0),

	/* top of loop */
	/*6 */ NETVM_OP(LDI, 4, RWSEG, 0, 0),
	/*7 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/*8 */ NETVM_OP(GEI, 0, 0, 0, 10),
	/*9 */ NETVM_BRIF_F(7), /* out of loop */
	/*10*/ NETVM_OP(PUSH, 0, 0, 0, 64), 	/* RWSEG is 0 in seg bits */
	/*11*/ NETVM_OP(PUSH, 0, 0, 0, 1), 
	/*12*/ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRSTR, 0, 0), 
	/*13*/ NETVM_OP(ADDI, 0, 0, 0, 1),
	/*14*/ NETVM_OP(STI, 4, RWSEG, 0, 0),
	/*15*/ NETVM_BR_B(9),

	/* out of loop */
	/*16*/ NETVM_OP(POP, 0, 0, 0, 1), 
	/*17*/ NETVM_OP(PUSH, 0, 0, 0, 72), 	/* RWSEG is 0 in seg bits */
	/*18*/ NETVM_OP(PUSH, 0, 0, 0, 1), 
	/*19*/ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRSTR, 0, 0), 
};


char hws1[] = "Hello World\n";
#define HWS_OFFSET      (0)
#define HWS_SIZE        (sizeof(hws1)-1)
struct meminit hwmi[] = {
	{(byte_t *) hws1, HWS_SIZE, ROSEG, HWS_OFFSET}
};


struct netvm_inst vm_prog_helloworld[] = {
	/*0 */ NETVM_CPOP_PRSTRI(ROSEG, HWS_OFFSET, HWS_SIZE), 
};


#define FIB_I0_OFFSET      (0)
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
	{(byte_t *) "\x00\x00\x00\x07", FIB_I0_SIZE, ROSEG, FIB_I0_OFFSET},
	{(byte_t *) fibs1, FIB_I1_SIZE, ROSEG, FIB_I1_OFFSET},
	{(byte_t *) fibs2, FIB_I2_SIZE, ROSEG, FIB_I2_OFFSET},
	{(byte_t *) fibs3, FIB_I3_SIZE, ROSEG, FIB_I3_OFFSET}
};

struct netvm_inst vm_prog_fib[] = {
	/* print initial string */
	/* 0 */ NETVM_CPOP_PRSTRI(ROSEG, FIB_I1_OFFSET, FIB_I1_SIZE),
	/* 1 */ NETVM_OP(LDI, 4, ROSEG, 0, FIB_I0_OFFSET),
	/* 2 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/* 3 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRDEC, 4, 0),
	/* 4 */ NETVM_CPOP_PRSTRI(ROSEG, FIB_I2_OFFSET, FIB_I2_SIZE),
	/* 5 */ NETVM_OP(PUSH, 0, 0, 0, NETVM_IADDR(10)),
	/* 6 */ NETVM_OP(CALL, 0, 0, 0, 0),
	/* 7 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRDEC, 4, 0),
	/* 8 */ NETVM_CPOP_PRSTRI(ROSEG, FIB_I3_OFFSET, FIB_I3_SIZE),
	/* 9 */ NETVM_OP(HALT, 0, 0, 0, 0),

	/* (v) <- Fib(n) */
	/*10 */ NETVM_OP(LDBPI, 1, 0, 0, 2), /* load 3rd(0-base) val BELOW bp */
	/*11 */ NETVM_OP(GTI, 0, 0, 0, 2),
	/*12 */ NETVM_BRIF_F(3),
	/*13 */ NETVM_OP(PUSH, 0, 0, 0, 1),
	/*14 */ NETVM_OP(RET, 1, 0, 0, 1),
	/*15 */ NETVM_OP(LDBPI, 1, 0, 0, 2),
	/*16 */ NETVM_OP(SUBI, 0, 0, 0, 1),
	/*17 */ NETVM_OP(PUSH, 0, 0, 0, NETVM_IADDR(10)),
	/*18 */ NETVM_OP(CALL, 0, 0, 0, 0),
	/*19 */ NETVM_OP(LDBPI, 1, 0, 0, 2),
	/*20 */ NETVM_OP(SUBI, 0, 0, 0, 2),
	/*21 */ NETVM_OP(PUSH, 0, 0, 0, NETVM_IADDR(10)),
	/*22 */ NETVM_OP(CALL, 0, 0, 0, 1),
	/*23 */ NETVM_OP(ADD, 0, 0, 0, 0),
	/*24 */ NETVM_OP(RET, 1, 0, 0, 1),
};


#define DUP1ST_PNUM     0
struct netvm_inst vm_prog_dup1st[] = {
	/* 0 */ NETVM_OP(LDI, 4, RWSEG, 0, DUP1ST_PNUM),
	/* 1 */ NETVM_OP(ADDI, 0, 0, 0, 1),
	/* 2 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/* 3 */ NETVM_OP(STI, 4, RWSEG, 0, DUP1ST_PNUM),
	/* 4 */ NETVM_OP(LEI, 0, 0, 0, 1),
	/* 5 */ NETVM_BRIF_F(4), 
	/* 6 */ NETVM_OP(PUSH, 0, 0, 0, 0),
	/* 7 */ NETVM_OP(PKDEL, 0, 0, 0, 0),
	/* 8 */ NETVM_OP(HALT, 0, 0, 0, 0),
	/* 9 */ NETVM_OP(PUSH, 0, 0, 0, 1), /* to packet 1 */
	/*10 */ NETVM_OP(PUSH, 0, 0, 0, 0), /* from packet 0 */
	/*11 */ NETVM_OP(PKCOPY, 0, 0, 0, 0), /* copy */
};


/* stored in RW seg */
#define BULK_DEST_ADDRLO	8
char bms1[] = "Hello World\n";
#define BMS1_OFFSET      (0)
#define BMS1_SIZE        (sizeof(bms1)-1)
char bms2[] = "\n";
#define BMS2_OFFSET      (BMS1_OFFSET + BMS1_SIZE)
#define BMS2_SIZE        (sizeof(bms2)-1)
struct meminit bmi[] = {
	{(byte_t *) bms1, BMS1_SIZE, ROSEG, BMS1_OFFSET},
	{(byte_t *) bms2, BMS2_SIZE, ROSEG, BMS2_OFFSET},
};


struct netvm_inst vm_prog_bulkmove[] = {
	/* only consider the 1st TCP packet with at least 16 bytes of payload */
	/* 0 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_PCLASS_XPORT, 0, 
			    NETVM_PRP_PRID, 0),
	/* 1 */ NETVM_OP(NEQI, 0, 0, 0, PRID_TCP),
	/* 2 */ NETVM_BRIF_F(10),
	/* 3 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_PLEN, 0),
	/* 4 */ NETVM_OP(LTI, 0, 0, 0, 16),
	/* 5 */ NETVM_BRIF_F(7),
	/* 6 */ NETVM_OP(LDI, 4, RWSEG, 0, DUP1ST_PNUM),
	/* 7 */ NETVM_OP(ADDI, 0, 0, 0, 1),
	/* 8 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/* 9 */ NETVM_OP(STI, 4, RWSEG, 0, DUP1ST_PNUM),
	/*10 */ NETVM_OP(LEI, 0, 0, 0, 1),
	/*11 */ NETVM_BRIF_F(4),
	/*12 */ NETVM_OP(PUSH, 0, 0, 0, 0),
	/*13 */ NETVM_OP(PKDEL, 0, 0, 0, 0),
	/*14 */ NETVM_OP(HALT, 0, 0, 0, 0),

	/* First print the first 16 bytes of the payload */
	/*15 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_POFF, 0),
	/*16 */ NETVM_OP(ORHI, 0, 0, 0, (NETVM_SEG_ISPKT<<NETVM_UA_SEG_HI_OFF)),
	/*17 */ NETVM_OP(PUSH, 0, 0, 0, BULK_DEST_ADDRLO), /* Address 0 */
	/*18 */ NETVM_OP(ORHI, 0, 0, 0, (RWSEG << NETVM_UA_SEG_HI_OFF)),
	/*19 */ NETVM_OP(PUSH, 0, 0, 0, 16), /* Length 16 */
	/*20 */ NETVM_OP(MOVE, 0, 0, 0, 0),
	/*21 */ NETVM_OP(LDI, 4, RWSEG, 0, (BULK_DEST_ADDRLO + 0)),
	/*22 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRHEX, 4, 0),
	/*23 */ NETVM_OP(LDI, 4, RWSEG, 0, (BULK_DEST_ADDRLO + 4)),
	/*24 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRHEX, 4, 0),
	/*25 */ NETVM_OP(LDI, 4, RWSEG, 0, (BULK_DEST_ADDRLO + 8)),
	/*26 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRHEX, 4, 0),
	/*27 */ NETVM_OP(LDI, 4, RWSEG, 0, (BULK_DEST_ADDRLO + 12)),
	/*28 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRHEX, 4, 0),
	/*29 */ NETVM_CPOP_PRSTRI(ROSEG, BMS2_OFFSET, BMS2_SIZE),

	/* Next put "hello world" into the beginning of the packet */
	/*30 */ NETVM_OP(PUSH, 0, 0, 0, BMS1_OFFSET),
	/*31 */ NETVM_OP(ORHI, 0, 0, 0, (ROSEG << NETVM_UA_SEG_HI_OFF)),
	/*32 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_TCP, 0, NETVM_PRP_POFF, 0),
	/*33 */ NETVM_OP(ORHI, 0, 0, 0, (NETVM_SEG_ISPKT<<NETVM_UA_SEG_HI_OFF)),
	/*34 */ NETVM_OP(PUSH, 0, 0, 0, BMS1_SIZE),
	/*35 */ NETVM_OP(MOVE, 0, 0, 0, 0),
};


#define HD_IDX          (0)
#define HD_PKNADDR      (8)
char hds1[] = "Packet ";
#define HDS1_OFFSET     (0)
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
	{(byte_t *) hds1, HDS1_SIZE, ROSEG, HDS1_OFFSET},
	{(byte_t *) hds2, HDS2_SIZE, ROSEG, HDS2_OFFSET},
	{(byte_t *) hds3, HDS3_SIZE, ROSEG, HDS3_OFFSET},
	{(byte_t *) hds4, HDS4_SIZE, ROSEG, HDS4_OFFSET},
	{(byte_t *) hds5, HDS5_SIZE, ROSEG, HDS5_OFFSET},
};

struct netvm_inst vm_prog_hexdump[] = {
	/* 0 */ NETVM_CPOP_PRSTRI(ROSEG, HDS1_OFFSET, HDS1_SIZE),
	/* 1 */ NETVM_OP(LDI, 8, RWSEG, 0, HD_PKNADDR),
	/* 2 */ NETVM_OP(ADDI, 0, 0, 0, 1),
	/* 3 */ NETVM_OP(DUP, 0, 0, 0, 0),
	/* 4 */ NETVM_OP(STI, 8, RWSEG, 0, HD_PKNADDR),
	/* 5 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRDEC, 8, 0),
	/* 6 */ NETVM_CPOP_PRSTRI(ROSEG, HDS2_OFFSET, HDS2_SIZE),
	/* 7 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_NONE, 0, NETVM_PRP_PLEN, 0),
	/* 8 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRDEC, 8, 0),
	/* 9 */ NETVM_CPOP_PRSTRI(ROSEG, HDS3_OFFSET, HDS3_SIZE),
	/*10 */ NETVM_OP(PUSH, 0, 0, 0, 0),
	/*11 */ NETVM_OP(STI, 8, RWSEG, 0, HD_IDX),

	/* LOOP top */
	/*12 */ NETVM_OP(LDI, 8, RWSEG, 0, HD_IDX),
	/*13 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_NONE, 0, NETVM_PRP_PLEN, 0),
	/*14 */ NETVM_OP(GE, 0, 0, 0, 0),
	/*15 */ NETVM_BRIF_F(13),
	/* END LOOP TEST */
	/*16 */ NETVM_OP(LDI, 8, RWSEG, 0, HD_IDX),
	/*17 */ NETVM_OP(MODI, 0, 0, 0, 16),
	/*18 */ NETVM_BRIF_F(2),
	/*19 */ NETVM_CPOP_PRSTRI(ROSEG, HDS5_OFFSET, HDS5_SIZE),
	/*20 */ NETVM_OP(LDI, 8, RWSEG, 0, HD_IDX),
	/*21 */ NETVM_OP(ORHI, 0, 0, 0,
			 NETVM_PDESC_HI(0, PRID_NONE, 0, NETVM_PRP_POFF)),
	/*22 */ NETVM_OP(LDPD, 1, 0, 0, 0),
	/*23 */ NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRHEX, 1, 2),

	/*24 */ NETVM_OP(LDI, 8, RWSEG, 0, HD_IDX),
	/*25 */ NETVM_OP(ADDI, 0, 0, 0, 1),
	/*26 */ NETVM_OP(STI, 8, RWSEG, 0, HD_IDX),
	/*27 */ NETVM_BR_B(15),
	/* LOOP END */

	/*28 */ NETVM_CPOP_PRSTRI(ROSEG, HDS4_OFFSET, HDS4_SIZE),
	/*29 */ NETVM_OP(PUSH, 0, 0, 0, 0),
	/*30 */ NETVM_OP(PKDEL, 0, 0, 0, 0),
	/*31 */ NETVM_OP(HALT, 0, 0, 0, 0),
};


char meqs1[] = "\x45\x00\x00\x34";
#define MEQ_VAL_OFFSET      (0)
#define MEQ_VAL_SIZE        (sizeof(meqs1)-1)
char meqs2[] = "\xff\x00\xff\xff";
#define MEQ_MASK_OFFSET     (MEQ_VAL_OFFSET + MEQ_VAL_SIZE)
#define MEQ_MASK_SIZE       (sizeof(meqs2)-1)
struct meminit meqsi[] = {
	{(byte_t *) meqs1, MEQ_VAL_SIZE, ROSEG, MEQ_VAL_OFFSET},
	{(byte_t *) meqs2, MEQ_MASK_SIZE, ROSEG, MEQ_MASK_OFFSET},
};


struct netvm_inst vm_prog_maskeq[] = {
	/* 0 */ NETVM_PDIOP(LDPFI, 0, 0, PRID_PCLASS_NET, 0, NETVM_PRP_SOFF, 0),
	/* 1 */ NETVM_OP(EQI, 0, 0, 0, NETVM_PF_INVALID),
	/* 2 */ NETVM_BRIF_F(8), 

	/* Compare 1st _SIZE bytes of pkt 0's network header */ 
	/* use 'x' bit of LDPFI to make the SOFF get generated in UA form */
	/* 3 */ NETVM_PDIOP(LDPFI, 1, 0, PRID_PCLASS_NET, 0, NETVM_PRP_SOFF, 0),
	/* 4 */ NETVM_OP(PUSH, 0, 0, 0, MEQ_VAL_OFFSET), 
	/* 5 */ NETVM_OP(ORHI, 0, 0, 0, (ROSEG << NETVM_UA_SEG_HI_OFF)),
	/* 6 */ NETVM_OP(PUSH, 0, 0, 0, MEQ_MASK_OFFSET), 
	/* 7 */ NETVM_OP(ORHI, 0, 0, 0, (ROSEG << NETVM_UA_SEG_HI_OFF)),
	/* 8 */ NETVM_OP(PUSH, 0, 0, 0, MEQ_MASK_SIZE), 
	/* 9 */ NETVM_OP(MSKCMP, 0, 0, 0, 0),
};


struct netvm_program {
	struct netvm_inst *code;
	unsigned codelen;
	const char *desc;
	int nopkts;
	int filter;
	struct meminit *mi;
	int nmi;
} vm_progs[] = {
	{ vm_prog_istcp, array_length(vm_prog_istcp),
	  "istcp -- Test if the packet has a TCP header", 0, 0, NULL, 0 }, 
	{ vm_prog_tcperr, array_length(vm_prog_tcperr),
	  "tcperr -- Test if the packet is TCP and has errors",
	    0, 0, NULL, 0 }, 
	{ vm_prog_isudp, array_length(vm_prog_isudp),
	  "isudp -- Test if the packet is UDP", 0, 0, NULL, 0 }, 
	{ vm_prog_fixcksum, array_length(vm_prog_fixcksum),
	  "fixcksum -- fix checksums on packets", 0, 1, NULL, 0 },
	{ vm_prog_toggledf, array_length(vm_prog_toggledf),
	  "toggledf -- toggle the df bit in the IP header and fix checksums",
	  0, 1, NULL, 0 },
	{ vm_prog_count10, array_length(vm_prog_count10),
	  "count10 -- print out 10 '.'s followed by a newline", 1, 1, NULL, 0 },
       	{ vm_prog_helloworld, array_length(vm_prog_helloworld),
	  "hello-world -- print out 'hello world' from a preinitialized string",
	   1, 1, hwmi, array_length(hwmi) }, 
	{ vm_prog_fib, array_length(vm_prog_fib),
	  "fib -- compute Xth fibonacci number", 1, 1, fibi, 
	  array_length(fibi) }, 
	{ vm_prog_dup1st, array_length(vm_prog_dup1st),
	  "dup1st -- duplicate the first packet and discard rest", 0, 1, NULL, 
	   0 }, 
	{ vm_prog_bulkmove, array_length(vm_prog_bulkmove),
	  "bulkmove -- Bulk move data in and out of the 1st 16-byte TCPpacket",
	  0, 1, bmi, array_length(bmi) }, 
	{ vm_prog_hexdump, array_length(vm_prog_hexdump),
	  "hexdump -- Hex dump the packets", 0, 1, hdi, array_length(hdi)}, 
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
	for (i = 0; i < array_length(vm_progs); ++i) {
		str_fmt(pdesc, sizeof(pdesc), "Program %2u: %s\n", i,
			vm_progs[i].desc);
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
	while (!(rv = optparse_next(&optparser, &opt))) {
		if (opt->ch == 'p') {
			if (opt->val.uint_val >= array_length(vm_progs))
				usage();
			prognum = opt->val.uint_val;
		}
	}
	if (rv < argc)
		usage();
}


void init_memory(struct netvm *vm, struct meminit *mi, size_t nmi)
{
	while (nmi > 0) {
		abort_unless(mi->off < vm->msegs[mi->seg].len
			     && mi->len < vm->msegs[mi->seg].len - mi->off);
		memcpy(vm->msegs[mi->seg].base + mi->off, mi->init, mi->len);
		++mi;
		--nmi;
	}
}


void print_vmret(int vmrv, int ec, uint pc, uint64_t rc)
{
	if (vmrv == 0) {
		fprintf(stderr, "VM provided no return value\n");
	} else if (vmrv == 1) {
		fprintf(stderr, "VM returned value %x\n", (uint)rc);
	} else if (vmrv == -1) {
		fprintf(stderr, "VM returned error @%u: %s\n", pc, netvm_estr(ec));
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
	print_vmret(vmrv, vm->error, vm->pc, rc);
}


static void send_clr_packets(struct netvm *vm, int npkt)
{
	int i;
	struct pktbuf *p;
	for (i = 0; i < NETVM_MAXPKTS; ++i) {
		p = netvm_clr_pkt(vm, i, 1);
		if (p) {
			if (pkb_pack(p) < 0)
				err("Error packing packet for writing");
			if (pkb_file_write(p, stdout) < 0)
				err("Error writing out packet %d", npkt);
			pkb_free(p);
		}
	}
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

	while (pkb_file_read(&p, stdin) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packets");
		++npkt;
		netvm_restart(vm);
		netvm_load_pkt(vm, p, 0);
		init_memory(vm, mi, nmi);
		vmrv = netvm_run(vm, -1, &rc);

		if ((vmrv == 1) && rc)
			++npass;
		fprintf(stderr, "Packet %5u: ", npkt);
		print_vmret(vmrv, vm->error, vm->pc, rc);

		if (filter && vmrv >= 0)
			send_clr_packets(vm, npkt);
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

	register_std_proto();
	pkb_init(1);

	prog = &vm_progs[prognum];
	file_emitter_init(&fe, (prog->filter ? stderr : stdout));
	netvm_init(&vm, vm_stack, array_length(vm_stack));
	netvm_set_mseg(&vm, 0, vm_memory[0], sizeof(vm_memory[0]), 
		       NETVM_SEG_RDWR);
	netvm_set_mseg(&vm, 1, vm_memory[1], sizeof(vm_memory[1]), 
		       NETVM_SEG_RD|NETVM_SEG_MO);
	if (init_netvm_std_coproc(&vm, &vmcps) < 0)
		errsys("Error initializing NetVM coprocessors");
	set_outport_emitter(&vmcps.outport, &fe.fe_emitter);

	if (!prog->filter)
		vm.matchonly = 1;
	netvm_set_code(&vm, prog->code, prog->codelen);
	if ((rv = netvm_validate(&vm)) < 0)
		err("Error validating program %d: %s\n", prognum,
		    netvm_estr(rv));

	if (prog->nopkts) {
		run_without_packets(&vm, prog->mi, prog->nmi);
	} else {
		run_with_packets(&vm, prog->filter, prog->mi, prog->nmi);
	}

	return 0;
}
