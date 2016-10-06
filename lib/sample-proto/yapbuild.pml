import "std.pml";

BEGIN {
	pkt_new(0, 0);
	pdu_insert(pkt, @tcp);
	pdu_insert(pkt, @ip);
	pdu_insert(pkt, @yap);
	pdu_insert(pkt, @eth);
	fix_lens(0);
	fix_csums(0);
	print "Old tag: 0x", %04x%yap.tag;
	print "Old sum: 0x", %04x%yap.csum;
	yap.tag = 0xcafe;
	fix_csum(yap);
	print "New tag: 0x", %04x%yap.tag;
	print "New sum: 0x", %04x%yap.csum;
	send 0;
}
