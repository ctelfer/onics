# String reference parameters and return values
#

int offme = 1;
str astring[16] = "foo bar baz ook ";


sref sf2(sref r, int len)
{
	return &r[0,len];
}

sref sf1(int off, sref r)
{
	r = sf2(&r[off+2], 6);
	return &r[2];
}

BEGIN {
	sref lr;
	lr = sf1(4, &astring);
	print "'", lr, "'\n";
}
