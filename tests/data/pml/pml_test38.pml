# Test wrapping a raw data packet and pushing space down for headers.
#

{
	pdu_insert(pkt, @tcp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);

	ip.saddr = 1.2.3.4;
	ip.daddr = 5.6.7.8;
	ip.ttl = 64;
	tcp.sport = 11111;
	tcp.dport = 22222;
	tcp.ack = 1;
	tcp.psh = 1;
	tcp.seqn = 12345678;
	tcp.ackn = 87654321;

	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);
}
