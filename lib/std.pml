#
# Utilities to help build packets
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


int mk_tcpipeth_pn(int pn) 
{
	len = 14 + 20 + 20;
	pkt_new(pn, 2048-256);
	parse_push_back(pn, @eth);
	$(pn)eth.ethtype = 0x800;
	parse_push_back(pn, @ip);
	$(pn)ip.proto = 6;
	parse_push_back(pn, @tcp);
	fix_dltype(pn);
	return 0;
}


int mk_tcpipeth() 
{
	return mk_tcpipeth_pn(0);
}


int mk_udpipeth_pn(int pn) 
{
	len = 14 + 20 + 8;
	pkt_new(pn, 2048-256);
	parse_push_back(pn, @eth);
	$(pn)eth.ethtype = 0x800;
	parse_push_back(pn, @ip);
	$(pn)ip.proto = 17;
	parse_push_back(pn, @udp);
	fix_dltype(pn);
	return 0;
}


int mk_udpipeth() 
{
	return mk_udpipeth_pn(0);
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
# VLAN Constants and utilities
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
