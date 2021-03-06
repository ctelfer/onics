# IP header checksum computation
#
# variables, packet fields, loops, packet byte strings
# if statements, print, multiply, equals, greater than
# plus, minus, right-shift, binary AND, packet header pattern
#

?- ip -? {
	off = 0;
	hlen = ip.hlen;
	csum = 0;

	if ( ip.ihl * 4 == ip.hlen ) {
		print "header lengths match";
	} else {
		print "header lengths don't match";
	} 

	while ( hlen > 0 ) {
		csum = csum + ip[off, 2];
		off = off + 2;
		hlen = hlen - 2;
	}

	while ( csum >> 16 ) {
		csum = (csum & 0xFFFF) + (csum >> 16);
	}

	if ( csum == 0xFFFF ) {
		print "Good checksum";
	} else {
		print "Bad checksum";
	}
}
