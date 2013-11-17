#
# Utilities to help build packets
#

int pkt_splice(str p, str s)
{
	str post;

	pn = str_seg(&p);
	cutlen = str_len(&p);
	off = str_addr(&p);
	inslen = str_len(&s);

	if (not str_ispkt(&p)) {
		return -1;
	}

	if (cutlen == inslen) {
		p = s;
		return 0;
	} 

	if (cutlen > inslen) {
		pkt_cut_d(&p[0, cutlen - inslen]);
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


