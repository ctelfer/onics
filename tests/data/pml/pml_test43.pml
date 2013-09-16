# IPv6 address parsing
#
?- ip6.saddr == fe80::222:faff:fea7:6990 -? {
	print "Found searched for address";
}
?- ip6.saddr =~ fe80::/64 -? {
	print "Found searched for /64 subnet";
}
?- ip6.saddr =~ fe80::222:faff:0000:0000/96 -? {
	print "Found searched for /96 subnet";
}
