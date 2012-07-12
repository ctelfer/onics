# Packet field manipulation, proper truncation of scalar assignments.
#
?- tcp -? { 
	ip[3,2] = 0xf00ba4;
	x = 2;
	ip.daddr[x] = \xbbaa;
}
