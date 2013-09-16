# Various references in all three types of rules

int Numpkts = 5;

BEGIN {
	print "Hello World";
}

?- tcp -? { print "%d", tcp.rst; Numpkts = Numpkts + 1; }

END {
	print "Total of ", Numpkts, " TCP packets seen";
}
