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

#
# Simple aliases for simple packet operations
#

inline pkt_headroom() { pkt.hlen }
inline pkt_tailroom() { pkt.tlen }
inline pkt_headroom_pn(int pn) { $(pn)pkt.hlen }
inline pkt_tailroom_pn(int pn) { $(pn)pkt.tlen }


void fix()
{
	fix_lens(0);
	fix_csums(0);
}


void fix_pn(int pn)
{
	fix_lens(pn);
	fix_csums(pn);
}


# Pop outermost header if present
void pdu_pop()
{
	if ($(0, 1)pdu)
		pdu_delete($(0, 1)pdu);
}


void pdu_pop_pn(int pn)
{
	if ($(pn, 1)pdu)
		pdu_delete($(pn, 1)pdu);
}


#
# Packet data splicing
#  - replace one string with another inserting or removing
#    space in the packet as required
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


#
# Simple packet creation functions
#

void mk_tcp_pn(int pn) 
{
	pkt_new(pn, 2048-256);
	pdu_insert(pkt, @eth);
	pdu_insert(eth, @ip);
	pdu_insert(ip, @tcp);
	fix_len(ip);
	fix_csum(ip);
	fix_csum(tcp);
}


void mk_tcp() 
{
	mk_tcp_pn(0);
}


void mk_udp_pn(int pn) 
{
	pkt_new(pn, 2048-256);
	pdu_insert(pkt, @eth);
	pdu_insert(eth, @ip);
	pdu_insert(ip, @udp);
	fix_len(ip);
	fix_csum(ip);
}


void mk_udp() 
{
	mk_udp_pn(0);
}


void mk_arp_pn(int pn)
{
	pkt_new(pn, 0);
	pdu_insert(pkt, @eth);
	pdu_insert(eth, @arp);
}


void mk_arp()
{
	mk_arp_pn(0);
}



#
# host() primitive
#  - return true if either src or dest address matches the packet
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
	pdu_update($(pn)eth);
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
	pdu_update($(pn)eth);
}


void vlan_pop()
{
	vlan_pop_pn(0);
}


#
# VXLAN constants
#

const VXLAN_PORT = 4789;


#
# Wrap utilities
#

void eth_wrap()
{
	pdu_insert(pkt, @eth);
}


void ip_wrap()
{
	pdu_insert(pkt, @ip);
}


void ip6_wrap()
{
	pdu_insert(pkt, @ip6);
}


void icmp_wrap()
{
	pdu_insert(pkt, @icmp);
}


void icmp6_wrap()
{
	pdu_insert(pkt, @icmp6);
}


void tcp_wrap()
{
	pdu_insert(pkt, @tcp);
}


void udp_wrap()
{
	pdu_insert(pkt, @udp);
}


void gre_wrap()
{
	pdu_insert(pkt, @gre);
}


void gre_encap()
{
	pdu_insert(pkt, @gre);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);
}


void gre_decap()
{
	if (eth and eth.index == 1 and
	    ip and ip.index == 2 and
	    gre and gre.index == 3) {
		pdu_delete(eth);
		pdu_delete(ip);
		pdu_delete(gre);
	}
}


void nvgre_wrap()
{
	pdu_insert(pkt, @nvgre);
}


void nvgre_encap()
{
	pdu_insert(pkt, @nvgre);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);
}


void nvgre_decap()
{
	if (eth and eth.index == 1 and
	    ip and ip.index == 2 and
	    nvgre and nvgre.index == 3) {
		pdu_delete(eth);
		pdu_delete(ip);
		pdu_delete(nvgre);
	}
}


void vxlan_wrap()
{
	pdu_insert(pkt, @vxlan);
}


void vxlan_encap()
{
	pdu_insert(pkt, @vxlan);
	pdu_insert(pkt, @udp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);
}


void vxlan_decap()
{
	if (eth and eth.index == 1 and
	    ip and ip.index == 2 and
	    udp and udp.index == 3 and udp.dport == VXLAN_PORT and
	    vxlan and vxlan.index == 4) {
		pdu_delete(eth);
		pdu_delete(ip);
		pdu_delete(udp);
		pdu_delete(vxlan);
	}
}


#
# MPLS Labels
#

inline mpls_nlabels() { str_len(mpls.header) / 4 }

inline mpls_get_label(int l) { mpls.header[(l * 4), 3] >> 4 }

inline mpls_get_tc(int l) { (mpls.header[(l * 4) + 2, 1] >> 1) & 0x7 }

inline mpls_get_bos(int l) { mpls.header[(l * 4) + 2, 1] & 0x1 }

inline mpls_get_ttl(int l) { mpls.header[(l * 4) + 3, 1] & 0xFF }

void mpls_set_label(int l, int x) {
	old = mpls.header[(l * 4), 4]; 
	mpls.header[(l * 4), 4] = (old & 0x00000FFF) | ((x & 0xFFFFF) << 12);
}

void mpls_set_tc(int l, int x) {
	old = mpls.header[(l * 4), 4]; 
	mpls.header[(l * 4), 4] = (old & 0xFFFFF1FF) | ((x & 0x7) << 9);
}

void mpls_set_bos(int l, int x) {
	old = mpls.header[(l * 4), 4]; 
	mpls.header[(l * 4), 4] = (old & 0xFFFFFEFF) | ((x & 0x1) << 8);
}

void mpls_set_ttl(int l, int x) {
	old = mpls.header[(l * 4), 4]; 
	mpls.header[(l * 4), 4] = (old & 0xFFFFFF00) | (x & 0xFF);
}

inline mpls_nlabels_pn(int pn) {
	str_len($(pn)mpls.header) / 4
}

inline mpls_get_label_pn(int pn, int l) {
	$(pn)mpls.header[(l * 4), 3] >> 4
}

inline mpls_get_tc_pn(int pn, int l) {
	($(pn)mpls.header[(l * 4) + 2, 1] >> 1) & 0x7
}

inline mpls_get_bos_pn(int pn, int l) {
	$(pn)mpls.header[(l * 4) + 2, 1] & 0x1
}

inline mpls_get_ttl_pn(int pn, int l) {
	$(pn)mpls.header[(l * 4) + 3, 1] & 0xFF
}

void mpls_set_label_pn(int pn, int l, int x) {
	old = $(pn)mpls.header[(l * 4), 4]; 
	$(pn)mpls.header[(l * 4), 4] = (old & 0x00000FFF) | ((x & 0xFFFFF) << 12);
}

void mpls_set_tc_pn(int pn, int l, int x) {
	old = $(pn)mpls.header[(l * 4), 4]; 
	$(pn)mpls.header[(l * 4), 4] = (old & 0xFFFFF1FF) | ((x & 0x7) << 9);
}

void mpls_set_bos_pn(int pn, int l, int x) {
	old = $(pn)mpls.header[(l * 4), 4]; 
	$(pn)mpls.header[(l * 4), 4] = (old & 0xFFFFFEFF) | ((x & 0x1) << 8);
}

void mpls_set_ttl_pn(int pn, int l, int x) {
	old = $(pn)mpls.header[(l * 4), 4]; 
	$(pn)mpls.header[(l * 4), 4] = (old & 0xFFFFFF00) | (x & 0xFF);
}

void mpls_push_pn(int pn, int label, int tc, int ttl)
{
	val = ((label & 0xFFFFF) << 12) | ((tc & 0x7) << 9) | (ttl & 0xFF);
	if (not $(pn)mpls) {
		pdu_insert($(pn)pkt, @mpls);
		val = val | 0x100;
	} else {
		pkt_ins_d(pn, str_addr($(pn)mpls.header), 4);
		pkt_adj_off(pn, @mpls, 0, 0, -4);
	}
	$(pn)mpls[0, 4] = val;
}

int mpls_pop_pn(int pn)
{
	val = 0;
	if ($(pn)mpls and $(pn)mpls.index == 1) {
		val = $(pn)mpls[0, 4];
		pkt_cut_u($(pn)mpls.header[0, 4]);
		if (str_len($(pn)mpls.header) <= 0)
			pdu_delete($(pn)mpls);
	}
	return val;
}

void mpls_push(int label, int tc, int ttl)
{
	mpls_push_pn(0, label, tc, ttl);
}

int mpls_pop()
{
	return mpls_pop_pn(0);
}


#
# RC4-based PRNG
#
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
