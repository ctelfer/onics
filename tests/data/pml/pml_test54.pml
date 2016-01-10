# VLAN push/pop test
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
# VLAN utilites
#


const ETYPE_C_VLAN = 0x8100;
const ETYPE_S_VLAN = 0x88a8;

inline etype_is_vlan(int etype) { 
	etype == ETYPE_C_VLAN or etype == ETYPE_S_VLAN
}


inline vlan_present(int pnum)
{
	$(pnum)eth and etype_is_vlan($(pnum)eth[12,2])
}


void vlan_push(int pnum, int tpid, int tci)
{
	if (not $(pnum)eth)
		return 0;
	pkt_ins_d(pnum, str_addr($(pnum)eth[0]) + 12, 4);
	$(pnum)eth[12,4] = (tpid << 16) | (tci & 0xFFFF);
	parse_update($(pnum)eth);
}


void vlan_pop(int pnum)
{
	if (not vlan_present(pnum))
		return 0;
	pkt_cut_u($(pnum)eth[12,4]);
}


BEGIN {
	mk_udpipeth();
	eth.src = 02:01:00:00:00:00;
	eth.dst = 02:02:00:00:00:00;
	ip.saddr = 99.0.0.0;
	ip.daddr = 100.0.0.0;
	udp.dport = 53;
	udp.sport = 12345;
	udp.cksum = 1;
	pkt_splice(udp.payload, "FOOBARBAZ");
	vlan_push(0, ETYPE_C_VLAN, 1000);
	fix_lens(0);
	fix_csums(0);
	send_no_free 0;

	eth.vlan0.tpid = ETYPE_S_VLAN;
	eth.vlan0.vid = 2000;
	send_no_free 0;

	vlan_pop(0);
	fix_lens(0);
	send;
}

