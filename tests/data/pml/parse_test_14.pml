# Basic declarations within a function.
#
int foo(int x) {
	int y;
	y = x - 1;
	z = x - 2;
	return x + y +  z;
}

BEGIN { print "foo(10) = ", foo(10), "\n"; }
