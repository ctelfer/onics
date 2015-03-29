# Check for for stack overflow due to improper function cleanup.
#
str mystr[6];

void foo(int x, str s, int y)
{
	s[0,1] = 0xff;
}

BEGIN {
	i = 0;
	while (i < 500000) {
		foo(i, mystr, i - 2);
		i = i + 1;
	}
}
