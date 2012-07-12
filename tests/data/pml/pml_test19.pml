# Packet data extraction
#
?- pkt.payload[12,2] =~ \x0800 -? { 
	print "Got an IP packet in ethernet\n"; 
}

?- pkt[&pkt.payload + 12, 2] == \x0800 -? {
	print "found by indirection\n";
}
