# String reference intrinsics
#

int x = 5; # make sure address is not 0 
str astring[16] = "foo bar baz ook";
str gref;
str nullgref;

int str_func(int x, str pref)
{
	print "Length of string = ", str_len(&pref);
	print "Address of string = ", str_addr(&pref);
	print "'Is Packet' of string = ", str_ispkt(&pref);
	print "Segment of string = ", str_seg(&pref);
	print "'Is null' of string = ", str_isnull(&pref);
}

int str_func_call(str lref)
{
	return str_func(1, &lref);
}


BEGIN {
	str lref;
	str nulllref;

	print "First testing by direct reference";
	print "Length of string = ", str_len(&astring);
	print "Address of string = ", str_addr(&astring);
	print "'Is Packet' of string = ", str_ispkt(&astring);
	print "Segment of string = ", str_seg(&astring);
	print "'Is null' of string = ", str_isnull(&astring);

	print "\n";
	&gref = &astring;
	print "Next testing by global reference";
	print "Length of string = ", str_len(&gref);
	print "Address of string = ", str_addr(&gref);
	print "'Is Packet' of string = ", str_ispkt(&gref);
	print "Segment of string = ", str_seg(&gref);
	print "'Is null' of string = ", str_isnull(&gref);

	print "\n";
	&lref = &astring;
	print "Next testing by local reference";
	print "Length of string = ", str_len(&lref);
	print "Address of string = ", str_addr(&lref);
	print "'Is Packet' of string = ", str_ispkt(&lref);
	print "Segment of string = ", str_seg(&lref);
	print "'Is null' of string = ", str_isnull(&lref);

	print "\n";
	print "Next testing by local parameter from direct ref";
	str_func(1, &astring);

	print "\n";
	print "Next testing by local parameter from global variable ref";
	str_func(1, &gref);

	print "\n";
	print "Next testing by local parameter from local variable ref";
	str_func(1, &lref);

	print "\n";
	print "Next testing by local parameter from parameter variable ref";
	str_func_call(&astring);

	print "\n";
	print "Next testing null global reference";
	print "Length of string = ", str_len(&nullgref);
	print "Address of string = ", str_addr(&nullgref);
	print "'Is Packet' of string = ", str_ispkt(&nullgref);
	print "Segment of string = ", str_seg(&nullgref);
	print "'Is null' of string = ", str_isnull(&nullgref);

	print "\n";
	print "Next testing null local reference";
	print "Length of string = ", str_len(&nulllref);
	print "Address of string = ", str_addr(&nulllref);
	print "'Is Packet' of string = ", str_ispkt(&nulllref);
	print "Segment of string = ", str_seg(&nulllref);
	print "'Is null' of string = ", str_isnull(&nulllref);
}
