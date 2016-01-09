#
# ONICS
# Copyright 2014-2016
# Christopher Adam Telfer
#
# std.pml - standard library utilities for PML
#
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

int pkt_splice(str p, str s)
{
	str post;

	pn = str_seg(p);
	cutlen = str_len(p);
	off = str_addr(p);
	inslen = str_len(s);

	if (not str_ispkt(p)) {
		return -1;
	}

	if (cutlen == inslen) {
		p = s;
		return 0;
	} 

	if (cutlen > inslen) {
		pkt_cut_d(p[0, cutlen - inslen]);
	} else { 
		pkt_ins_u(pn, off, inslen - cutlen);
	}

	&post = str_mkref(1, pn, off, inslen);
	post = s;

	return 0;
}


void mk_tcp_pn(int pn) 
{
	pkt_new(pn, 2048-256);
	parse_push_back(pn, @eth);
	$(pn)eth.ethtype = 0x800;
	parse_push_back(pn, @ip);
	$(pn)ip.proto = 6;
	parse_push_back(pn, @tcp);
	fix_dltype(pn);
}


void mk_tcp() 
{
	mk_tcp_pn(0);
}


void mk_udp_pn(int pn) 
{
	pkt_new(pn, 2048-256);
	parse_push_back(pn, @eth);
	$(pn)eth.ethtype = 0x800;
	parse_push_back(pn, @ip);
	$(pn)ip.proto = 17;
	parse_push_back(pn, @udp);
	fix_dltype(pn);
}


void mk_udp() 
{
	mk_udp_pn(0);
}


void mk_arp_pn(int pn)
{
	pkt_new(pn, 14 + 28);
	parse_push_back(pn, @eth);
	$(pn)eth.ethtype = 0x806;
	parse_push_back(pn, @arp);
	fix_dltype(pn);
}


void mk_arp()
{
	mk_arp_pn(0);
}



#
# host() primitive
#

inline host_pn(int pn, str addr) {
	((str_len(addr) == 4) and $(pn)ip and
		($(pn)ip.saddr == addr or $(pn)ip.daddr == addr))
	or ((str_len(addr) == 16) and $(pn)ip6 and
		($(pn)ip6.saddr == addr or $(pn)ip6.daddr == addr))
	or ((str_len(addr) == 6) and $(pn)eth and
		($(pn)eth.src == addr or $(pn)eth.dst == addr))
}

inline host(str addr) { host_pn(0, addr) }

#
# Ethernet constants and utilities
#

const ETYPE_C_VLAN = 0x8100;
const ETYPE_S_VLAN = 0x88a8;

inline etype_is_vlan(int etype) {
	etype == ETYPE_C_VLAN or etype == ETYPE_S_VLAN
}


inline vlan_present_pn(int pn)
{
	$(pn)eth and etype_is_vlan($(pn)eth[12,2])
}


inline vlan_present() { vlan_present_pn(0) }


void vlan_push_pn(int pn, int vid)
{
	if (not $(pn)eth)
		return 0;
	pkt_ins_d(pn, str_addr($(pn)eth[0]) + 12, 4);
	$(pn)eth[12,4] = (ETYPE_C_VLAN << 16) | (vid & 0xFFFF);
	parse_update($(pn)eth);
}


void vlan_push(int vid)
{
	vlan_push_pn(0, vid);
}


void vlan_pop_pn(int pn)
{
	if (not vlan_present_pn(pn))
		return 0;
	pkt_cut_u($(pn)eth[12,4]);
	parse_update($(pn)eth);
}


void vlan_pop()
{
	vlan_pop_pn(0);
}


void fix()
{
	fix_lens(0);
	fix_csums(0);
	fix_dltype(0);
}


void fix_pn(int pn)
{
	fix_lens(pn);
	fix_csums(pn);
	fix_dltype(pn);
}


#
# Wrap utilities
#

void eth_wrap()
{
	parse_push_front(0, @eth);
	fix_dltype(0);
}


void ip_wrap()
{
	parse_push_front(0, @ip);
	fix_dltype(0);
}


void ip6_wrap()
{
	parse_push_front(0, @ip6);
	fix_dltype(0);
}


void icmp_wrap()
{
	parse_push_front(0, @icmp);
	fix_dltype(0);
}


void icmp6_wrap()
{
	parse_push_front(0, @icmp6);
	fix_dltype(0);
}


void tcp_wrap()
{
	parse_push_front(0, @tcp);
	fix_dltype(0);
}


void udp_wrap()
{
	parse_push_front(0, @udp);
	fix_dltype(0);
}


void gre_wrap()
{
	parse_push_front(0, @gre);
	fix_dltype(0);
}


void nvgre_wrap()
{
	parse_push_front(0, @nvgre);
	fix_dltype(0);
}


# RC4-based PRNG
str rand_m[256];
int rand_i;
int rand_j;

void rand_init(str k)
{
	int b;

	rand_i = 0;
	while (rand_i < 256) {
		rand_m[rand_i, 1] = rand_i;
		rand_i = rand_i + 1;
	}

	rand_i = 0;
	rand_j = 0;
	while (rand_i < 256) {
		rand_j = (rand_j + rand_m[rand_i, 1] + k[rand_i % str_len(k), 1]) 
			& 0xFF;
		b = rand_m[rand_i, 1];
		rand_m[rand_i, 1] = rand_m[rand_j, 1];
		rand_m[rand_j, 1] = b;
		rand_i = rand_i + 1;
	}

	rand_i = 0;
	rand_j = 0;
}


int rand_byte()
{
	int b1;
	int b2;

	rand_i = (rand_i + 1) & 0xFF;
	rand_j = (rand_j + rand_m[rand_i, 1]) & 0xFF;
	b1 = rand_m[rand_i, 1];
	b2 = rand_m[rand_j, 1];
	rand_m[rand_i, 1] = b2;
	rand_m[rand_j, 1] = b1;

	return rand_m[(b1 + b2) & 0xFF, 1];
}


int rand_short()
{
	return rand_byte() << 8 | rand_byte();
}


int rand_int()
{
	return rand_byte() << 24 | rand_byte() << 16 |
               rand_byte() << 8  | rand_byte();
}


const MAC_TYPE_ANY = 0;
const MAC_TYPE_UNICAST = 1;
const MAC_TYPE_LOC_UNICAST = 2;
const MAC_TYPE_MULTICAST = 3;


void rand_mac(str mac, int type)
{
	mac[0,1] = rand_byte();
	if (type == MAC_TYPE_UNICAST)
		mac[0,1] = mac[0,1] & 0xFC;
	else if (type == MAC_TYPE_LOC_UNICAST)
		mac[0,1] = mac[0,1] & 0xFE | 2;
	else if (type == MAC_TYPE_MULTICAST)
		mac[0,1] = mac[0,1] | 1;
	mac[1,1] = rand_byte();
	mac[2,1] = rand_byte();
	mac[3,1] = rand_byte();
	mac[4,1] = rand_byte();
	mac[5,1] = rand_byte();
}
