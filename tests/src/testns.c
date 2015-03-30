/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * testns.c -- Test namespace API.
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
#include <stdio.h>
#include <string.h>

#include <cat/cat.h>
#include <cat/err.h>
#include <cat/pack.h>

#include "prid.h"
#include "ns.h"
#include "stdproto.h"
#include "util.h"

#define E(x) ERRCK((x) ? -1 : 0)

byte_t tcphdr[] = {
	'\x00', '\x16', '\x94', '\x53', '\x66', '\xa0', '\xde', '\x9d', '\x80',
	'\xba', '\x8a', '\x0c', '\x80', '\x18', '\x03', '\x59', '\xab', '\x0f',
	'\x00', '\x00',
};

byte_t iphdr[] = {
	'\x45', '\x10', '\x00', '\x34', '\xa1', '\x5c', '\x40', '\x00', '\x40',
	'\x06', '\x17', '\xfa', '\xc0', '\xa8', '\x00', '\x06', '\xc0', '\xa8',
	'\x00', '\x07',
};


byte_t addr0[4] = "\xc0\xa8\x00\x06";
byte_t addr1[4] = "\xc0\xa8\x00\x00";
byte_t mask1[4] = "\xff\xff\x00\x00";
byte_t addr2[4] = "\xc0\xa8\xFF\xFF";
byte_t addr3[4] = "\x7f\x00\x00\x00";
byte_t addr4[4] = "\x7f\xFF\xFF\xFF";
byte_t addr5[4] = "\xc0\x00\x00\x06";
byte_t mask5[4] = "\xf0\x00\x00\x0f";

byte_t saddr[4];
byte_t daddr[4];


unsigned long extract(byte_t * p, struct ns_pktfld *f)
{
	if (NSF_IS_INBITS(f->flags)) {
		return getbits(p, f->off * 8 + NSF_BITOFF(f->flags), f->len);
	} else if (f->len == 1) {
		byte_t b;
		unpack(p + f->off, f->len, "b", &b);
		return b;
	} else if (f->len == 2) {
		ushort h;
		unpack(p + f->off, f->len, "h", &h);
		return h;
	} else if (f->len == 4) {
		ulong w;
		unpack(p + f->off, f->len, "w", &w);
		return w;
	} else {
		err("invalid length: %ld\n", f->len);
		return -1; /* not reached */
	}
}


#define arr2raw(a,r) (r.data = a, r.len = sizeof(a), &r)

struct ns_namespace myipns =
	NS_NAMESPACE_I("ip", NULL, PRID_NONE, PRID_NONE, NULL, NULL, NULL, 0);

struct ns_elem *portsarr[32] = { 0 };
struct ns_namespace tcpports =
	NS_NAMESPACE_I("ports", NULL, PRID_TCP, PRID_PCLASS_XPORT, NULL, NULL,
		       portsarr, array_length(portsarr));
struct ns_elem *oddarr[2] = { 0 };
struct ns_namespace oddrange =
	NS_NAMESPACE_I("oddrange", NULL, PRID_TCP, PRID_PCLASS_XPORT, NULL, 
			NULL, oddarr, array_length(oddarr));

struct ns_scalar sshport = NS_UINT16_I("ssh", NULL, PRID_TCP, 22);
struct ns_scalar oddlo = NS_UINT16_I("low", NULL, PRID_TCP, 80);
struct ns_scalar oddhi = NS_UINT16_I("high", NULL, PRID_TCP, 92);


int main(int argc, char *argv[])
{
	struct ns_pktfld *f, *bf;
	struct ns_scalar *s;
	struct ns_elem *e;
	unsigned long v, lo, hi;

	E(register_std_proto());

	/* Namespace management */
	E(ns_add_elem(&oddrange, (struct ns_elem *)&oddlo));
	E(ns_add_elem(&oddrange, (struct ns_elem *)&oddhi));
	E(ns_add_elem(&tcpports, (struct ns_elem *)&oddrange));
	E(ns_add_elem(&tcpports, (struct ns_elem *)&sshport));
	E(!(e = ns_lookup(NULL, "tcp")));
	if (e->type != NST_NAMESPACE)
		err("\"tcp\" namespace isn't a namespace type: %d", e->type);
	E(ns_add_elem((struct ns_namespace *)e, (struct ns_elem *)&tcpports));


	/* Basic lookups */
	E(!(e = ns_lookup(NULL, "tcp.seqn")));
	printf("tcp.seqn is of type %d\n", e->type);

	E(!(e = ns_lookup(NULL, "tcp.sport")));
	f = (struct ns_pktfld *)e;
	E(!(e = ns_lookup(NULL, "tcp.ports.ssh")));
	s = (struct ns_scalar *)e;

	v = extract(tcphdr, f);
	printf("extracted source port %s tcp.ports.ssh (%lu vs %lu)\n",
	       (v == s->value) ? "matches" : "doesn't match", v, s->value);

	E(!(bf = (struct ns_pktfld *)ns_lookup(NULL, "tcp.syn")));
	printf("tcp.syn %s set\n", extract(tcphdr, bf) ? "is" : "is not");

	E(!(bf = (struct ns_pktfld *)ns_lookup(NULL, "tcp.ack")));
	printf("tcp.ack %s set\n", extract(tcphdr, bf) ? "is" : "is not");

	E(!(bf = (struct ns_pktfld *)ns_lookup(NULL, "tcp.psh")));
	printf("tcp.psh %s set\n", extract(tcphdr, bf) ? "is" : "is not");


	E(!(e = ns_lookup(NULL, "tcp.sport")));
	f = (struct ns_pktfld *)e;
	v = extract(tcphdr, f);
	E(!(e = ns_lookup(NULL, "tcp.ports.oddrange.low")));
	lo = ((struct ns_scalar *)e)->value;
	E(!(e = ns_lookup(NULL, "tcp.ports.oddrange.high")));
	hi = ((struct ns_scalar *)e)->value;
	printf("tcp.sport %s tcp.ports.oddrange\n",
	       ((lo <= v) && (hi >= v)) ? "matches" : "doesn't match");

	E(!(e = ns_lookup(NULL, "tcp.dport")));
	f = (struct ns_pktfld *)e;
	v = extract(tcphdr, f);
	printf("tcp.dport = %u\n", (unsigned)v);
	E(!(e = ns_lookup(NULL, "tcp.ports.oddrange")));
	printf("tcp.dport %s tcp.ports.oddrange\n",
	       ((lo <= v) && (hi >= v)) ? "matches" : "doesn't match");

	/* Bad lookups */
	E(ns_lookup(NULL, "a.b.c"));
	E(ns_lookup(NULL, "tcp.b.c"));
	E(ns_lookup(NULL, "tcp.ports.c"));
	printf("all bad lookup tests passed\n");

	E(!ns_add_elem(NULL, (struct ns_elem *)&myipns));

	ns_rem_elem((struct ns_elem *)&tcpports);
	E(ns_lookup(NULL, "tcp.ports.oddrange"));
	printf("successfully freed tcpns\n");

	unregister_std_proto();

	printf("testns: completed\n");

	return 0;
}
