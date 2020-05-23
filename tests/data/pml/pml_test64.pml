# Ensure udp checksum fix doesn't leave 0 checksum
{
	udp.payload[0,2] = 0x0ece; 
	fix_csums(0);
	if (udp.cksum == 0) {
		print "Zero UDP checksum after fixing!";
		exit(1);
	}
}
