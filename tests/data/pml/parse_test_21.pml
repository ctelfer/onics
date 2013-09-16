# Test parsing print statement with trailing comma.
#
BEGIN {
	print "Hello ",;
	print "World";
}
