# Intrinsics
#
# boolean AND, packet byte fields, immediate byte fields, intrinsics, print
#
inline isudp() { 
	eth and
	eth[12,2] == \x0800 and
	ip[9,1] == 17
}
?- isudp() -? {
	print "Found UDP";
}
