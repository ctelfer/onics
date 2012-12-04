/*
 * ONICS
 * Copyright 2012 
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
#include <cat/cattypes.h>
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


/* Dump a hex representation of the given data to out */
void hexdump(FILE *out, ulong addr, byte_t *p, ulong len);


#undef swap16
#undef swap32
#undef swap64

#define swap16(v) ( (((uint16_t)(v) << 8) & 0xFF00) | \
		    (((uint16_t)(v) >> 8) & 0xFF) )

#define swap32(v) ( (((uint32_t)(v) << 24) & 0xFF000000u) | \
		    (((uint32_t)(v) << 8) & 0xFF0000u)    | \
		    (((uint32_t)(v) >> 8) & 0xFF00u)      | \
		    (((uint32_t)(v) >> 24) & 0xFFu) )

#define swap64(v) ( (((uint64_t)(v) & 0xFF) << 56) | \
		    (((uint64_t)(v) >> 56) & 0xFF) | \
		    (((uint64_t)(v) & 0xFF00) << 40) | \
		    (((uint64_t)(v) >> 40) & 0xFF00) | \
		    (((uint64_t)(v) & 0xFF0000) << 24) | \
		    (((uint64_t)(v) >> 24) & 0xFF0000) | \
		    (((uint64_t)(v) & 0xFF000000u) << 8) | \
		    (((uint64_t)(v) >> 8) & 0xFF000000u) )

/* sign extend to 64 bits */
#define signx64(v, nbits) \
	((uint64_t)(v) | ((uint64_t)0 - ((v) & (1 << ((nbits) - 1)))))


/* returns the numerical value of the min(8, len) bytes in big-endian format */
uint64_t be64val(void *p, size_t len);


/* sets the byte string pointed to by 'p' to the numeric value in 'val' */
/* modulo 2^(min(8, len) * 8) */
void wrbe64(void *p, size_t len, uint64_t val);


#endif /* __util_h */
