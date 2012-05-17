int fib(x) {
	if (x < 2) {
		return 0;
	}
	return fib(x-1) + fib(x-2);
}

BEGIN {
	if (fib(7) == 21) {
		print "got fib(7) == 21";
	}
}
