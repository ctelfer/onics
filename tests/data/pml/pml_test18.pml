# Test packet and header creation intrinsics.
#
BEGIN {
	pkt_new(0, 12);
	pdu_insert(pkt, @tcp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @eth);
	tcp.payload = "Hello World\n";
	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);

	pkt_new(1, 14);
	pdu_insert($(1)pkt, @eth);
	pdu_insert($(1)eth, @ip);
	pdu_insert($(1)ip, @tcp);
	$(1)tcp.payload = "Goodbye World\n";
	fix_dltype(1);
	fix_lens(1);
	fix_csums(1);

	send;
}
