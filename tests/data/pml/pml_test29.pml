# String reference intrinsics
#

int x = 5; # make sure address is not 0 
str astring[16] = "foo bar baz ook";
sref gref;
sref nullgref;

int sref_func(int x, sref pref)
{
	print "Length of string = ", sref_len(&pref), "\n";
	print "Address of string = ", sref_addr(&pref), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&pref), "\n";
	print "Segment of string = ", sref_seg(&pref), "\n";
	print "'Is null' of string = ", sref_isnull(&pref), "\n";
}

int sref_func_call(sref lref)
{
	return sref_func(1, &lref);
}


BEGIN {
	sref lref;
	sref nulllref;

	print "First testing by direct reference\n";
	print "Length of string = ", sref_len(&astring), "\n";
	print "Address of string = ", sref_addr(&astring), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&astring), "\n";
	print "Segment of string = ", sref_seg(&astring), "\n";
	print "'Is null' of string = ", sref_isnull(&astring), "\n";

	print "\n\n";
	gref = &astring;
	print "Next testing by global reference\n";
	print "Length of string = ", sref_len(&gref), "\n";
	print "Address of string = ", sref_addr(&gref), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&gref), "\n";
	print "Segment of string = ", sref_seg(&gref), "\n";
	print "'Is null' of string = ", sref_isnull(&gref), "\n";

	print "\n\n";
	lref = &astring;
	print "Next testing by local reference\n";
	print "Length of string = ", sref_len(&lref), "\n";
	print "Address of string = ", sref_addr(&lref), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&lref), "\n";
	print "Segment of string = ", sref_seg(&lref), "\n";
	print "'Is null' of string = ", sref_isnull(&lref), "\n";

	print "\n\n";
	print "Next testing by local parameter from direct ref\n";
	sref_func(1, &astring);

	print "\n\n";
	print "Next testing by local parameter from global variable ref\n";
	sref_func(1, &gref);

	print "\n\n";
	print "Next testing by local parameter from local variable ref\n";
	sref_func(1, &lref);

	print "\n\n";
	print "Next testing by local parameter from parameter variable ref\n";
	sref_func_call(&astring);

	print "\n\n";
	print "Next testing null global reference\n";
	print "Length of string = ", sref_len(&nullgref), "\n";
	print "Address of string = ", sref_addr(&nullgref), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&nullgref), "\n";
	print "Segment of string = ", sref_seg(&nullgref), "\n";
	print "'Is null' of string = ", sref_isnull(&nullgref), "\n";

	print "\n\n";
	print "Next testing null local reference\n";
	print "Length of string = ", sref_len(&nulllref), "\n";
	print "Address of string = ", sref_addr(&nulllref), "\n";
	print "'Is Packet' of string = ", sref_ispkt(&nulllref), "\n";
	print "Segment of string = ", sref_seg(&nulllref), "\n";
	print "'Is null' of string = ", sref_isnull(&nulllref), "\n";
}
