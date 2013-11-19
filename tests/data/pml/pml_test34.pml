# Test 'send' with packet argument.
#
BEGIN {
	pkt_new(0, 12);
	parse_push_front(0, @tcp);
	parse_push_front(0, @ip);
	parse_push_front(0, @eth);
	tcp.payload = "Hello World\n";
	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);

	send 0;

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

	send 1;

	print "Still running";
}
