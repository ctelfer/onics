# Test 'drop' with packet argument.
#
{
	# drop the packet we got
	drop 0;

	# build a new one
	pkt_new(1, 14);
	pdu_insert($(1)pkt, @eth);
	pdu_insert($(1)eth, @ip);
	pdu_insert($(1)ip, @tcp);
	$(1)tcp.payload = "Goodbye World\n";
	fix_dltype(1);
	fix_lens(1);
	fix_csums(1);

	send 1;

	print "got to end with packet";
}
