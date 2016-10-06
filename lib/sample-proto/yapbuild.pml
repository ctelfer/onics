import "std.pml";

BEGIN {
	pkt_new(0, 0);
	pdu_insert(pkt, @tcp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @yap);
	pdu_insert(pkt, @eth);
	fix_lens(0);
	fix_csums(0);
	send 0;
}
