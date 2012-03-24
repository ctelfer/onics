

var Numpkts = 5;

BEGIN {
	print "Hello World";
}

?- tcp -? { print "%d", tcp.rst; Numpkts = Numpkts + 1; }

END {
	print "Total of %d TCP packets seen\n", Numpkts;
}
