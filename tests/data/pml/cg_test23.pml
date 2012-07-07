{ print "Packet\n"; }

?- tcp and tcp.payload =~ `l.*ld` -? { 
	print "Hello world?\n";
}
