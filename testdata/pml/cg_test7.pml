?- tcp -? { 
	ip[3,2] = 0xf00ba4;
	x = 3;
	ip.daddr[x] = \xbbaa;
}
