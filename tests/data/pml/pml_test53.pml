# Test creating a new data packet and wrapping headers.
#
str pay[] = "hello world";
BEGIN {
	pkt_new(0, str_len(pay));
	pdu_insert(pkt, @tcp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);

	eth.src = 00:11:22:33:44:55;
	eth.dst = 00:66:77:88:99:aa;
	ip.saddr = 1.2.3.4;
	ip.daddr = 5.6.7.8;
	ip.ttl = 64;
	tcp.sport = 11111;
	tcp.dport = 22222;
	tcp.ack = 1;
	tcp.psh = 1;
	tcp.seqn = 12345678;
	tcp.ackn = 87654321;
	tcp.payload = pay;

	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);
	send;
}
