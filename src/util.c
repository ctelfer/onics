#include "util.h"
#include <ctype.h>

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
	v = *p++ & RIGHTMASK(bitoff);
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
		v = (v << 8) | *p++;
	}

	/* mask off trailing bits that don't matter */
	if (bitlen > 0)
		v = (v << bitlen) | ((*p & LEFTMASK(bitlen)) >> (8 - bitlen));

	return v;
}


/*
 * 01001011 11001001 11001110
 * off 3 len 3:  set to 0x10
 *
 */

void setbits(byte_t *p, ulong bitoff, uint bitlen, ulong val)
{
	int x;
	unsigned char m;

	abort_unless(p && (bitlen <= sizeof(ulong) << 3));

	/* get to the correct start byte */
	p += bitoff >> 8;
	bitoff &= 7;

	/* header */
	x = (8 - bitoff) & 7;
	if (x > bitlen)
		x = bitlen;
	if (x > 0) {
		m = ~(RIGHTMASK(bitoff) & LEFTMASK(bitoff + x));
		*p &= m;
		*p++ |= (val >> (bitlen - x)) << (8 - bitoff - x);
		bitlen -= x;
	}

	/* body */
	while (bitlen >= 8) {
		*p++ = (val >> (bitlen - 8)) & 0xFF;
		bitlen -= 8;
	}

	/* trailer */
	if (bitlen > 0) {
		*p = (*p & ~LEFTMASK(bitlen)) | 
		     ((val & RIGHTMASK(bitlen)) << (8 - bitlen));
	}
}


int getbit(const byte_t *p, ulong n)
{
	abort_unless(p);
	p += n >> 3;
	return (*p & (0x80 >> (n & 7))) != 0;
}


void setbit(byte_t *p, ulong n, int v)
{
	abort_unless(p);
	p += n >> 3;
	if (v)
		*p |= 0x80 >> (n & 7);
	else
		*p &= ~(0x80 >> (n & 7));
}


#define CHOF(x)	(isprint(x) ? (x) : '.')
void hexdump(FILE *out, ulong addr, byte_t *p, ulong len)
{
	int i;
	ulong aoff = 0;

	while (len > 16) { 
		fprintf(out, "    %06lx:  "
			     "%02x %02x %02x %02x %02x %02x %02x %02x "
			     "%02x %02x %02x %02x %02x %02x %02x %02x  "
			     "|%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|\n", addr+aoff,
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
			CHOF(p[0]), CHOF(p[1]), CHOF(p[2]), CHOF(p[3]),
			CHOF(p[4]), CHOF(p[5]), CHOF(p[6]), CHOF(p[7]),
			CHOF(p[8]), CHOF(p[9]), CHOF(p[10]), CHOF(p[11]),
			CHOF(p[12]), CHOF(p[13]), CHOF(p[14]), CHOF(p[15]));
		p += 16;
		len -= 16;
		aoff += 16;
	}

	if (len > 0) {
		fprintf(out, "    %06lx:  ", addr + aoff);
		for (i = 0; i < len; ++i)
			fprintf(out, "%02x ", p[i]);
		for (; i < 16; ++i)
			fprintf(out, "   ");
		fprintf(out, " |");
		for (i = 0; i < len; ++i)
			fprintf(out, "%c", CHOF(p[i]));
		fprintf(out, "|\n");
	}
}


uint64_t be64val(void *vp, size_t len)
{
	uint64_t x = 0;
	byte_t *p = vp;
	switch(len) {
	case 0: break;
	default:
	case 8: x = *p++;
	case 7: x = (x << 8) | *p++;
	case 6: x = (x << 8) | *p++;
	case 5: x = (x << 8) | *p++;
	case 4: x = (x << 8) | *p++;
	case 3: x = (x << 8) | *p++;
	case 2: x = (x << 8) | *p++;
	case 1: x = (x << 8) | *p++;
	}
	return x;
}
