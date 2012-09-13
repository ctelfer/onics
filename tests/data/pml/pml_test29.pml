# String reference intrinsics
#

int x = 5; # make sure address is not 0 
str astring[16] = "foo bar baz ook";
str gref;
str nullgref;

int str_func(int x, str pref)
{
	print "Length of string = ", str_len(&pref), "\n";
	print "Address of string = ", str_addr(&pref), "\n";
	print "'Is Packet' of string = ", str_ispkt(&pref), "\n";
	print "Segment of string = ", str_seg(&pref), "\n";
	print "'Is null' of string = ", str_isnull(&pref), "\n";
}

int str_func_call(str lref)
{
	return str_func(1, &lref);
}


BEGIN {
	str lref;
	str nulllref;

	print "First testing by direct reference\n";
	print "Length of string = ", str_len(&astring), "\n";
	print "Address of string = ", str_addr(&astring), "\n";
	print "'Is Packet' of string = ", str_ispkt(&astring), "\n";
	print "Segment of string = ", str_seg(&astring), "\n";
	print "'Is null' of string = ", str_isnull(&astring), "\n";

	print "\n\n";
	&gref = &astring;
	print "Next testing by global reference\n";
	print "Length of string = ", str_len(&gref), "\n";
	print "Address of string = ", str_addr(&gref), "\n";
	print "'Is Packet' of string = ", str_ispkt(&gref), "\n";
	print "Segment of string = ", str_seg(&gref), "\n";
	print "'Is null' of string = ", str_isnull(&gref), "\n";

	print "\n\n";
	&lref = &astring;
	print "Next testing by local reference\n";
	print "Length of string = ", str_len(&lref), "\n";
	print "Address of string = ", str_addr(&lref), "\n";
	print "'Is Packet' of string = ", str_ispkt(&lref), "\n";
	print "Segment of string = ", str_seg(&lref), "\n";
	print "'Is null' of string = ", str_isnull(&lref), "\n";

	print "\n\n";
	print "Next testing by local parameter from direct ref\n";
	str_func(1, &astring);

	print "\n\n";
	print "Next testing by local parameter from global variable ref\n";
	str_func(1, &gref);

	print "\n\n";
	print "Next testing by local parameter from local variable ref\n";
	str_func(1, &lref);

	print "\n\n";
	print "Next testing by local parameter from parameter variable ref\n";
	str_func_call(&astring);

	print "\n\n";
	print "Next testing null global reference\n";
	print "Length of string = ", str_len(&nullgref), "\n";
	print "Address of string = ", str_addr(&nullgref), "\n";
	print "'Is Packet' of string = ", str_ispkt(&nullgref), "\n";
	print "Segment of string = ", str_seg(&nullgref), "\n";
	print "'Is null' of string = ", str_isnull(&nullgref), "\n";

	print "\n\n";
	print "Next testing null local reference\n";
	print "Length of string = ", str_len(&nulllref), "\n";
	print "Address of string = ", str_addr(&nulllref), "\n";
	print "'Is Packet' of string = ", str_ispkt(&nulllref), "\n";
	print "Segment of string = ", str_seg(&nulllref), "\n";
	print "'Is null' of string = ", str_isnull(&nulllref), "\n";
}
