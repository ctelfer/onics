# String reference parameters and return values
#

int offme = 1;
str astring[16] = "foo bar baz ook ";


str sf2(str r, int len)
{
	return r[0,len];
}

str sf1(int off, str r)
{
	&r = sf2(r[off+2], 6);
	return r[2];
}

BEGIN {
	str lr;
	&lr = sf1(4, astring);
	print "'", lr, "'";
}
