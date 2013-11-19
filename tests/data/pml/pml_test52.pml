# Test 'exists' implicit fields
#
int I = 0;
{ 
	I = I + 1;
	print "Packet: ", I;
	print "ip.opt.exists: ", ip.opt.exists; 
	print "tcp.exists: ", tcp.exists; 
	print "tcp.mss.kind.exists: ", tcp.mss.kind.exists; 
	print "udp.sport.exists: ", udp.sport.exists;
	print "";
	drop; 
}
