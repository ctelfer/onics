# Recursion
#
# We should be able to handle both types of recursion.
#

int fib(int x);
int fib2a(int x);
int fib2b(int x);
int fib2c(int x);

# self recursion
int fib(int x) {
	if (x <= 2) {
		return 1;
	}
	return fib(x-1) + fib(x-2);
}


# mutual recursion
int fib2a(int x) {
	if (x <= 2) {
		return 1;
	}
	return fib2b(x) + fib2c(x);
}

int fib2b(int x) {
	return fib2a(x-1);
}


int fib2c(int x) {
	return fib2b(x-1);
}



BEGIN {
	if (fib(7) == 13) {
		print "got fib(7) == 13\n";
	}

	if (fib2a(1) == 1) {
		print "got fib2a(1) == 1\n";
	}
	if (fib2a(2) == 1) {
		print "got fib2a(2) == 1\n";
	}
	if (fib2a(3) == 2) {
		print "got fib2a(3) == 2\n";
	}
	if (fib2a(4) == 3) {
		print "got fib2a(4) == 3\n";
	}
	if (fib2a(5) == 5) {
		print "got fib2a(5) == 5\n";
	}
	if (fib2a(6) == 8) {
		print "got fib2a(6) == 8\n";
	}
	if (fib2a(7) == 13) {
		print "got fib2a(7) == 13\n";
	}
	if (fib2a(8) == 21) {
		print "got fib2a(8) == 21\n";
	}
}
