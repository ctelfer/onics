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
