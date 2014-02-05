# Test packet and header creation intrinsics and pkt_cut_d().
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


int mk_tcpipeth(int pn) 
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

BEGIN {
	mk_tcpipeth(0);
	ip.saddr = 192.168.0.2;
	ip.daddr = 192.168.0.1;
	tcp.sport = 12345;
	tcp.dport = 80;
	pkt_splice(tcp.payload, "HTTP GET / 1.0\n\n");
	fix_lens(0);
	fix_csums(0);
	send;
}
