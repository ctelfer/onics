# Prototype and unused function test.
#

int bar(int x, int y);

int baz(str s);

int foo(int x)
{
	return bar(x, x + 1);
}

int bar(int x, int y)
{
	return x + 2 * y;
}


void xyzzy(str s)
{
	s[0,4] = 0xDEADC0DE;
}


int baz(str s)
{
	s[0] = 1;
	s[1] = 2;
	s[2] = 3;
	s[4] = 4;
	xyzzy(s);
	return 0;
}


BEGIN {
	foo(3);
	x = 0;
}
