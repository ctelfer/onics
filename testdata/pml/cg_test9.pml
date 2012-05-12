# Kristin's test part 2
# (variable assignment so the test can't be optimized out (yet))
BEGIN {
	x = 4;
	y = 6;
	if ( x + y == 10 ) {
		print "it's true!  4 + 6 = 10\n";
	}
}
