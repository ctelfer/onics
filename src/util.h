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
ulong getbits(const byte_t * p, ulong off, uint len);
void setbits(byte_t * p, ulong off, uint len, ulong val);

/* return 1 if bit #n is set in p */
int getbit(const byte_t * p, ulong n);
/* set bit n in p, if v or clr bit n in p if !v */
void setbit(byte_t * p, ulong n, int v);


/* Dump a hex representation of the given data to out */
void hexdump(FILE *out, ulong addr, byte_t *p, ulong len);


#endif /* __util_h */
