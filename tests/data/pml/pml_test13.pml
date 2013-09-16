# Basic function declaration and call.
#
# addition, call, local variables, parameters, equals, print
# 
int test(int a, int b) { 
	return a + b;
}

BEGIN {
	a = 2;
	b = 3;
	a = test(a, b);
	if (a == 5) {
		print "I got the right value";
	}
}
