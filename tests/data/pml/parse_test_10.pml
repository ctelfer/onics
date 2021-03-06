# Recursion Test
#
# We should be able to handle both types of recursion.
#

int fib(int x);
int fib2a(int x);
int fib2b(int x);
int fib2c(int x);

# self recursion
int fib(int x) {
	if (x < 2) {
		return 0;
	}
	return fib(x-1) + fib(x-2);
}


# mutual recursion
int fib2a(int x) {
	if (x < 2) {
		return 0;
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
	if (fib(7) == 21) {
		print "got fib(7) == 21";
	}

	if (fib2a(7) == 21) {
		print "got fib(7) == 21";
	}
}
