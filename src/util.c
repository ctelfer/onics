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


/*
 * 01001011 11001001 11001110
 * off 3 len 2: bitlen = 5 
 * 00011111  (0x100 >> 3 - 1) == 0x20 - 1 == 31 = 0x1F
 * 11111000  -(0x100 >> 5) == -0x08 == 0xff...f8
 *
 */


unsigned long bitfield(byte_t *p, size_t bitoff, size_t bitlen)
{
  unsigned long v;

  abort_unless(bitlen <= sizeof(unsigned long) << 3);
  p += bitoff >> 3;
  v = *p & ((256 >> (bitoff & 7)) - 1);

  bitlen += (bitoff & 7);
  while ( bitlen >= 8 ) {
    bitlen -= 8;
    v = (v << 8) | *p++;
  }
  v &= -(256 >> (bitlen & 7));

  /* shift into position */
  v >>= (8 - (bitlen & 7)) & 7;

  return v;
}
