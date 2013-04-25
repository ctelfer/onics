# Packet data extraction
#
?- pkt.payload[12,2] =~ \x0800 -? { 
	print "Got an IP packet in ethernet\n"; 
}

?- pkt[str_addr(&pkt.payload) + 12, 2] == 0x0800 -? {
	print "found by indirection\n";
}
