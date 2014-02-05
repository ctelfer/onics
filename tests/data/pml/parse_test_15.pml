# String references in various forms.
#

str astring[16] = "foo bar baz ook ";

int foo(str x, int off)
{
	return x[off];
}


str bar(str r, int off)
{
	return r[off+4, str_len(r) - off - 8];
}


str baz(str r, int off)
{
	return bar(r[off+2], 2);
}


{
	str r;
	str r2;

	&r = astring;
	r[4,4] = "kid ";
	r[8,4] = \x40404040;
	y = foo(r, 12);
	z = foo(astring, 0);

}

BEGIN {
	str r;
	str r2;
	&r = astring;
	&r2 = bar(r, 0);
	&r = bar(r, 4);
	&r2 = bar(astring, 0);
	&r = bar(astring, 4);
}
