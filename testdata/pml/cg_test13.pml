func test(a, b) { 
	return a + b;
}

BEGIN {
	a = 2;
	b = 3;
	a = test(a, b);
	if (a == 5) {
		print "I got the right value\n";
	}
}
