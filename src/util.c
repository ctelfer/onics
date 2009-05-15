#include "util.h"

uint16_t ones_sum_h(void *p, uint16_t len, uint16_t val)
{
  uint32_t sum = val;
  int rem = len & 1;
  uint16_t *hp, t;
  byte_t *b;

  /* main loop */
  len >>= 1;
  hp = (uint16_t *)p;
  while ( len-- )
    sum += *hp++;

  /* add remaining byte */
  if ( rem ) {
    t = 0;
    b = (byte_t *)&t;
    *b = *(byte_t *)hp;
    sum += t;
  }

  while ( sum >> 16 ) 
    sum = (sum & 0xFFFF) + (sum >> 16);

  return (uint16_t)sum;
}

uint16_t ones_sum(void *p, size_t len, uint16_t val)
{
  uint16_t sum = val;
  while ( len > 65534 ) {
    sum = ones_sum_h(p, len, sum);
    len -= 65534;
    p += 65534;
  }
  return ones_sum_h(p, len, sum);
}


#define LEFTMASK(bits) (-(0x100 >> (bits)))
#define RIGHTMASK(bits) ((0x100 >> (bits)) - 1)


/*
 * 01001011 11001001 11001110
 * off 3 len 2: bitlen = 5 
 * 00011111  (0x100 >> 3 - 1) == 0x20 - 1 == 31 = 0x1F
 * 11111000  -(0x100 >> 5) == -0x08 == 0xff...f8
 *
 */


unsigned long getbitfield(const byte_t *p, size_t bitoff, size_t bitlen)
{
  unsigned long v;

  abort_unless(p && bitlen <= sizeof(unsigned long) << 3);

  /* get to the correct start byte */
  p += bitoff >> 3;
  bitoff &= 7;

  /* XXX currently, this will fail, if the bitlen is near the size of */
  /* long, but overlaps multiple bytes */
  /* extract header from first byte */
  v = *p & RIGHTMASK(bitoff);

  /* add in remaining bytes */
  bitlen += bitoff;
  while ( bitlen >= 8 ) {
    bitlen -= 8;
    v |= (v << 8) | *p++;
  }

  /* mask off trailing bits that don't matter */
  v &= LEFTMASK(bitlen);

  /* shift into position */
  v >>= (8 - bitlen) & 7;

  return v;
}


/*
 * 01001011 11001001 11001110
 * off 3 len 3:  set to 0x10
 *
 */

void setbitfield(byte_t *p, size_t bitoff, size_t bitlen, unsigned long val)
{
  int exlen;
  unsigned char m;

  abort_unless(p && (bitlen <= sizeof(unsigned long) << 3));

  /* get to the correct start byte */
  p += bitoff >> 8;
  bitoff &= 7;

  /* header */
  exlen = (8 - bitoff) & 7;
  if ( exlen > bitlen )
    exlen = bitlen;
  if ( exlen > 0 ) {
    m = (1 << (8 - bitoff)) - 1;
    m &= LEFTMASK(bitoff + exlen); /* clear rightmost bits if within 1 byte */
    *p &= m;
    /* the RIGHTMASK here should be unnecessary, but do for sanity sake */
    *p++ |= (val >> (bitlen - exlen)) & RIGHTMASK(exlen);
    bitlen -= exlen;
  }

  /* body */
  while ( bitlen >= 8 ) {
    *p++ = (val >> (bitlen - 8)) & 0xFF;
    bitlen -= 8;
  }

  /* trailer */
  if ( bitlen > 0 ) {
    *p &= LEFTMASK(bitlen);
    *p |= (val & RIGHTMASK(bitlen)) << (8 - bitlen);
  }
}
