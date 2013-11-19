# Test 'send_no_free' mixing with incoming packets.
#
{
	# build a new packet for '1' one
	pkt_new(1, 68);
	parse_push_back(1, @eth);
	parse_push_back(1, @ip);
	$(1)eth.ethtype = 0x0800;
	parse_push_back(1, @tcp);
	$(1)ip.proto = 6;
	$(1)tcp.payload = "Goodbye World\n";
	fix_dltype(1);
	fix_lens(1);
	fix_csums(1);

	send_no_free 1;

	print "got to end with packet";
	print "should get original and then new packet again";
}
