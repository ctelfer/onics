# Regular expressions
#
{ print "Packet"; }

?- tcp and tcp.payload =~ `l.*ld` -? { 
	print "Hello world?";
}
