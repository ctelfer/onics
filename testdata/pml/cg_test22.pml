#
# We should be able to handle both types of recursion.
#

int fib(x);
int fib2a(x);
int fib2b(x);
int fib2c(x);

# self recursion
int fib(x) {
	if (x <= 2) {
		return 1;
	}
	return fib(x-1) + fib(x-2);
}


# mutual recursion
int fib2a(x) {
	if (x <= 2) {
		return 1;
	}
	return fib2b(x) + fib2c(x);
}

int fib2b(x) {
	return fib2a(x-1);
}


int fib2c(x) {
	return fib2b(x-1);
}



BEGIN {
	if (fib(7) == 13) {
		print "got fib(7) == 13\n";
	}

	if (fib2a(3) == 2) {
		print "got fib2a(3) == 2\n";
	}

	if (fib2a(8) == 21) {
		print "got fib2a(8) == 21\n";
	}
}
