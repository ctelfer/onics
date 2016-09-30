/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * util.h -- API for generic utility functions for ONICS programs.
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
#ifndef __util_h
#define __util_h
#include <cat/cat.h>
#include <cat/emit_format.h>
#include <stdio.h>

/* 
 * Compute the 1s complement sum of 'len' bytes.  'val' holds the
 * checksum thusfar.  (usually starts at 0).  This function 
 * assumes that the checksum starts on a 2-byte aligned boundary.
 * Because a 1s complement sum is endian neutral, one can compute
 * the checksum and then swap the bytes of the result as a
 * post-processing step and get the same result as if the entire sum
 * were computed by first performing appropriate byte swapping when
 * reading the 16-bit values.  
 */
uint16_t ones_sum(void *p, ulong len, uint16_t val);

/*
 * Extract 'len' bits from a position of 'off' bits from p.
 * Assumes extracts in network byte order.
 *
 * 'off' and 'len' are in bits.  'off' treats bytes as "big endian" for
 * purposes of the address of bits.
 * The result is shifted so the last bit in the string is in the 1s position
 * of the return value.  'bitlen' must be <= sizeof(long) * CHAR_BIT
 *
 * Example use:  to extract the traffic class from an IPv6 header:
 *   uint8_t tclass = getbits((byte_t *)v6p, 4, 8);
 * Example use: to extract the flow label from an IPv6 header:
 *   uint32_t flowlabel = getbits((byte_t *)v6p, 12, 20);
 *   
 */
ulong getbits(const byte_t *p, ulong off, uint len);

/* set up to 32 bits in a byte array (delimited as above in getbits()) */
void setbits(byte_t *p, ulong off, uint len, ulong val);

/* return 1 if bit #n is set in p */
int getbit(const byte_t * p, ulong n);

/* set bit n in p, if v or clr bit n in p if !v */
void setbit(byte_t * p, ulong n, int v);


/* Dump a hex representation of the given data to a file */
void fhexdump(FILE *out, const char *pfx, ulong addr, byte_t *p, ulong len);

/* Dump a hex representation of the given data to string 's' of size 'slen' */
void shexdump(char *s, size_t slen, const char *pfx, ulong addr, byte_t *p,
	      ulong len);

/* Dump a hex representation of the given data to 'e' */
void emit_hex(struct emitter *e, const char *pfx, ulong addr, byte_t *p,
	      ulong len);

#undef swap16
#undef swap32

#define swap16(v) ( (((uint16_t)(v) << 8) & 0xFF00) | \
		    (((uint16_t)(v) >> 8) & 0xFF) )

#define swap32(v) ( (((uint32_t)(v) << 24) & 0xFF000000u) | \
		    (((uint32_t)(v) << 8) & 0xFF0000u)    | \
		    (((uint32_t)(v) >> 8) & 0xFF00u)      | \
		    (((uint32_t)(v) >> 24) & 0xFFu) )

#define signxul(v, nbits) \
	((ulong)(v) | -((v) & ((ulong)1 << ((nbits) - 1))))

/* returns the numerical value of the min(8, len) bytes in big-endian format */
ulong be32val(void *p, size_t len);

/* sets the byte string pointed to by 'p' to the numeric value in 'val' */
/* modulo 2^(min(4, len) * 8) */
void wrbe32(void *p, size_t len, ulong val);

/* Add bi-direcional mapping between an ethertype and prid */
/* Returns -1 if the mapping already exists or if either parameter is 0 */
int e2p_map_add(ushort etype, uint prid);

/* Remove a bi-directional mapping between an ethertype and prid */
void e2p_map_del(ushort etype);

/* Returns the associated PRID for a given ethertype. */
/* Returns PRID_NONE if there is no corresponding PRID. */
uint etypetoprid(ushort etype);

/* Returns the associated ethertype for a given PRID. */
/* Returns 0 if there is no corresponding ethertype. */
ushort pridtoetype(uint prid);

/* Returns the associated IP protocol number for a given PRID. */
/* Returns IPPROT_RESERVED if there is no corresponding protocol. */
uchar pridtoiptype(uint prid);

/* returns the number of characters written or short count on error.  */
/* should always return 17 characters and slen should always be 18. */
int ethtostr(char *s, void *ea, size_t slen);

/* returns the number of characters written or short count on error.  */
/* should always 16 or less characters and slen should always be >= 16. */
int iptostr(char *s, void *ipa, size_t slen);

/* returns the number of characters written or short count on error.  */
/* should always return 40 characters and slen should always be >= 40. */
int ip6tostr(char *s, void *ip6a, size_t slen);


/*
 * Find a header in an IPv6 header by protocol. Return NULL if not
 * found within maxlen bytes.  If nhp is not null it will point to the
 * header field that refers to 'proto'.  If proto < 0 then it returns
 * the pointer to the first byte after the IPv6 extension headers (with
 * nhpp pointing to the next header byte in the prior header.  ip6findh
 * returns NULL if there is some error in parsing the extension headers.
 */
byte_t *ip6findh(void *ip6p, ulong maxlen, int proto, byte_t **nhpp);

#endif /* __util_h */
