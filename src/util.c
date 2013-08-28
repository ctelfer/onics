/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * utils.c -- generic packet utility routines.
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

#include <ctype.h>
#include <cat/str.h>
#include "util.h"


/*
 * One should not call this function with a length value of
 * greater than 131072.  Otherwise it is possible for the
 * sum to overflow 32 bits of accumulation and thus come out
 * wrong.  This does not tend to be a problem with network
 * packets as even IPv6 frames top out at 65536 + 40 + 24 bytes.
 */
uint16_t ones_sum(void *p, ulong len, uint16_t val)
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
	p += bitoff >> 3;
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


#define CHOF(x)	((isprint(x) && ((x) <= 127)) ? (x) : '.')
void fhexdump(FILE *out, const char *pfx, ulong addr, byte_t *p, ulong len)
{
	int i;
	ulong aoff = 0;

	while (len > 16) {
		if (pfx != NULL)
			fputs(pfx, out);
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
		if (pfx != NULL)
			fputs(pfx, out);
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


void shexdump(char *s, size_t ssize, const char *pfx, ulong addr, byte_t *p,
	      ulong len)
{
	int i;
	int n;
	size_t scl;
	ulong aoff = 0;

	while (len > 16) {
		if (pfx != NULL) {
			scl = str_copy(s, pfx, ssize);
			if (scl >= ssize)
				return;
			ssize -= scl;
			s += scl;
		}

		n = snprintf(s, ssize, 
			     "    %06lx:  "
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

		if (n < ssize)
			return;
		s += n;
		ssize -= n;
	}

	if (len > 0) {
		if (pfx != NULL) {
			scl = str_copy(s, pfx, ssize);
			if (scl >= ssize)
				return;
			s += scl;
			ssize -= scl;
		}

		n = snprintf(s, ssize, "    %06lx:  ", addr + aoff);
		if (n < ssize)
			return;
		s += n;
		ssize -= n;

		for (i = 0; i < len; ++i) {
			n += snprintf(s, ssize, "%02x ", p[i]);
			if (n < ssize)
				return;
			s += n;
			ssize -= n;
		}
		for (; i < 16; ++i) {
			n += snprintf(s, ssize, "   ");
			if (n < ssize)
				return;
			s += n;
			ssize -= n;
		}

		n = snprintf(s, ssize, " |");
		if (n < ssize)
			return;
		s += n;
		ssize -= n;

		for (i = 0; i < len; ++i) {
			n = snprintf(s, ssize, "%c", CHOF(p[i]));
			if (n < ssize)
				return;
			s += n;
			ssize -= n;
		}
		snprintf(s, ssize, "|\n");
	}
}


void emit_hex(struct emitter *e, const char *pfx, ulong addr, byte_t *p,
	      ulong len)
{
	int i;
	ulong aoff = 0;

	while (len > 16) { 
		if (pfx != NULL)
			emit_string(e, pfx);
		emit_format(e, 
			    "    %06lx:  "
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
		if (pfx != NULL)
			emit_string(e, pfx);
		emit_format(e, "    %06lx:  ", addr + aoff);
		for (i = 0; i < len; ++i)
			emit_format(e, "%02x ", p[i]);
		for (; i < 16; ++i)
			emit_format(e, "   ");
		emit_format(e, " |");
		for (i = 0; i < len; ++i)
			emit_format(e, "%c", CHOF(p[i]));
		emit_format(e, "|\n");
	}
}


ulong be32val(void *vp, size_t len)
{
	ulong x = 0;
	byte_t *p = vp;
	switch (len) {
	case 0: break;
	default:
	case 4: x = *p++;
	case 3: x = (x << 8) | *p++;
	case 2: x = (x << 8) | *p++;
	case 1: x = (x << 8) | *p++;
	}
	return x;
}


void wrbe32(void *dp, size_t len, ulong x)
{
	byte_t *p = dp;
	switch (len) {
	case 0: break;
	default:
	case 4: *p++ = (x >> 24) & 0xFF;
	case 3: *p++ = (x >> 16) & 0xFF;
	case 2: *p++ = (x >> 8) & 0xFF;
	case 1: *p++ = x & 0xFF;
	}
}


int ethtostr(char *s, void *ea, size_t slen)
{
	byte_t *p = ea;
	if (slen < 18)
		return -1;
	return snprintf(s, slen, "%02x:%02x:%02x:%02x:%02x:%02x",
			p[0], p[1], p[2], p[3], p[4], p[5]);

}


int iptostr(char *s, void *ipa, size_t slen)
{
	byte_t *p = ipa;
	if (slen < 16)
		return -1;
	return snprintf(s, slen, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}


int ip6tostr(char *s, void *ip6a, size_t slen)
{
	int zs = 0, ze = 0;
	int ls = -1, le = -1;
	int i, n, si;
	byte_t *p = ip6a;
	if (slen < 40)
		return -1;

	/* find the longest set of contiguous zero half-words */
	for (i = 0; i < 16; i += 2) {
		if (p[i] != 0 || p[i+1] != 0) {
			if (ze - zs > le - ls) {
				ls = zs;
				le = ze;
			}
			zs = i + 2;
			ze = i + 2;
		} else {
			ze += 2;
		}
	}

	si = 0;
	for (i = 0; i < 16; i += 2) {
		if (i == ls) {
			s[si] = ':';
			s[si+1] = ':';
			s[si+2] = '\0';
			si += 2;
		} else if (i < ls || i >= le) {
			if (i != 0 && i != le)
				n = snprintf(s + si, slen - si, ":%0x",
					     (p[i] << 8 | p[i+1]));
			else
				n = snprintf(s + si, slen - si, "%0x",
					     (p[i] << 8 | p[i+1]));
			si += n;
		}	
	}
	return si;
}
