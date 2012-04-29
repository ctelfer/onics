const X = 53;
const Y = 4 * X;

var Global;
var another_global[40] = "hello world";
var broadcast_var[4] = ip.addr.broadcast;

?- ip.saddr =~ 127.0.0.0/24 -? {
	print "hi", x; 
}

{ } 

{ local = 3 + 5 | tcp[5,2]; }


?- ip -?  {
	a = 0;
	i = 0;
	csum = 0;
	while ( i < ip.hlen ) {
		csum = csum + tcp[i, 2];
		i = i + 2;
	}

	while ( csum > 0xFFFF ) {
		csum = (csum & 0xFFFF) + (csum >> 16) & 0xFFFF;
	}

	if ( (csum + ip[10,2]) & 0xFFFF != 0 ) {
		print "Bad checksum";
	} else {
		print "Good checksum";
	}

	ip.daddr = \x20304050;
	a = ip.saddr =~ ip.addr.localhost;
	a = ip.saddr =~ ip.addr.localnet;
}

