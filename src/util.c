#include "util.h"

uint16_t ones_sum_h(void *p, uint16_t len, uint16_t val)
{
	uint32_t sum = val;
	int rem = len & 1;
	uint16_t *hp, t;
	byte_t *b;

	/* main loop */
	len >>= 1;
	hp = (uint16_t *) p;
	while (len--)
		sum += *hp++;

	/* add remaining byte */
	if (rem) {
		t = 0;
		b = (byte_t *) & t;
		*b = *(byte_t *) hp;
		sum += t;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t) sum;
}


uint16_t ones_sum(void *p, ulong len, uint16_t val)
{
	uint16_t sum = val;
	while (len > 65534) {
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
ulong getbits(const byte_t * p, ulong bitoff, uint bitlen)
{
	ulong v;
	int n;

	abort_unless(p && bitlen <= sizeof(ulong) * 8);

	/* get to the correct start byte */
	p += bitoff >> 3;
	bitoff &= 7;

	/* extract header from first byte */
	v = *p & RIGHTMASK(bitoff);
	n = bitoff + bitlen;
	if (n < 8) {
		v &= LEFTMASK(n);
		v >>= 8 - n;
		bitlen = 0;
	} else {
		bitlen -= 8 - bitoff;
	}

	/* whole bytes in body */
	while (bitlen >= 8) {
		bitlen -= 8;
		v |= (v << 8) | *p++;
	}

	/* mask off trailing bits that don't matter */
	if (bitlen > 0) {
		v = (v << bitlen) | ((*p & LEFTMASK(bitlen)) >> (8 - bitlen));
	}

	return v;
}


/*
 * 01001011 11001001 11001110
 * off 3 len 3:  set to 0x10
 *
 */

void setbits(byte_t * p, ulong bitoff, uint bitlen, ulong val)
{
	int exlen;
	unsigned char m;

	abort_unless(p && (bitlen <= sizeof(ulong) << 3));

	/* get to the correct start byte */
	p += bitoff >> 8;
	bitoff &= 7;

	/* header */
	exlen = (8 - bitoff) & 7;
	if (exlen > bitlen)
		exlen = bitlen;
	if (exlen > 0) {
		m = (1 << (8 - bitoff)) - 1;
		/* clear rightmost bits if within 1 byte */
		m &= LEFTMASK(bitoff + exlen);
		*p &= m;
		/* XXX the RIGHTMASK here should be unnecessary */
		*p++ |= (val >> (bitlen - exlen)) & RIGHTMASK(exlen);
		bitlen -= exlen;
	}

	/* body */
	while (bitlen >= 8) {
		*p++ = (val >> (bitlen - 8)) & 0xFF;
		bitlen -= 8;
	}

	/* trailer */
	if (bitlen > 0) {
		*p &= LEFTMASK(bitlen);
		*p |= (val & RIGHTMASK(bitlen)) << (8 - bitlen);
	}
}


int getbit(const byte_t * p, ulong n)
{
	abort_unless(p);
	p += n >> 3;
	return (*p & (0x80 >> (n & 7))) != 0;
}


void setbit(byte_t * p, ulong n, int v)
{
	abort_unless(p);
	p += n >> 3;
	if (v)
		*p |= 0x80 >> (n & 7);
	else
		*p &= ~(0x80 >> (n & 7));
}
