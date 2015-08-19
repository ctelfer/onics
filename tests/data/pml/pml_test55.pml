# ICMPv6 generation test
#

BEGIN {
	pkt_new(0, 0);

	parse_push_front(0, @icmp6);
	parse_push_front(0, @ip6);
	parse_push_front(0, @eth);

	eth.src = 02:00:00:00:00:01;
	eth.dst = 02:00:00:00:00:02;
	ip6.saddr = fe80::1;
	ip6.daddr = fe80::2;
	ip6.hoplim = 64;
	icmp6.type = 128;
	icmp6.code = 0;

	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);

	send 0;
}

