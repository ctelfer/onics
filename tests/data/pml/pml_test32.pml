# void function declarations.
#

int x = 50;

void afunc() { x = 30; }

BEGIN {
	afunc();
	print x;
}
