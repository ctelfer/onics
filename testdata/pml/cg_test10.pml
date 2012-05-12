?- ip -? {
	off = 0;
	hlen = ip.hlen;
	csum = 0;

	if ( ip.ihl * 4 == ip.hlen ) {
		print "header lengths match\n";
	} else {
		print "header lengths don't match\n";
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
		print "Good checksum\n";
	} else {
		print "Bad checksum\n";
	}
}
