?- tcp -? { 
	ip[3,2] = 0xf00ba4;
	x = 2;
	ip.daddr[x] = \xbbaa;
	y = fix_all_len(0);
	y = fix_all_csum(0);
	#y = pkt_parse(0);
	#y = fix_all_csum(0);
}
