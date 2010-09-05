#ifndef __util_h
#define __util_h
#include <cat/cattypes.h>

uint16_t ones_sum(void *p, size_t len, uint16_t val);

/*
 * Extract 'bitlen' bits from a position of 'bitoff' bits from p.
 * Assumes extracts in network byte order.
 *
 * 'bitoff' and 'bitlen' are in bits
 * 'offset' treats bytes as "big endian"
 * The result is shifted so the last bit in the string is in the 1s position
 * of the return value.  'bitlen' must be <= sizeof(long) * CHAR_BIT
 *
 * Example use:  to extract the traffic class from an IPv6 header:
 *   uint8_t tclass = bitfield((byte_t *)v6p, 4, 8);
 * Example use: to extract the flow label from an IPv6 header:
 *   uint32_t flowlabel = bitfield((byte_t *)v6p, 12, 20);
 *   
 */
unsigned long getbitfield(const byte_t * p, size_t bitoff, size_t bitlen);
void setbitfield(byte_t * p, size_t bitoff, size_t bitlen, unsigned long val);

/* return 1 if bit #n is set in p */
int getbit(const byte_t * p, size_t n);
/* set bit n in p, if v or clr bit n in p if !v */
void setbit(byte_t * p, size_t n, int v);

#endif /* __util_h */
