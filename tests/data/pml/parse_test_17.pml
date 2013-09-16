# Braceless if and while statements
#

BEGIN {
	x = 0;
	y = 1;

	# simple one stmt 'if'
	if ( x )
		y = 2;

	# simple one stmt with 'print' as stmt
	if ( x == y )
		print "equal";

	# simple one stmt 'if-else'
	if ( y )
		x = 3;
	else
		y = 10;

	# simple one stmt 'while'
	while ( x < 5 )
		x = x + 1;

	# while with if-else for stmt
	while ( x < 10 )
		if ( x == 2 )
			x = 5;
		else
			x = x + 1;

	# stmtlist for 'if', stmt for 'else'
	if ( x ) {
		print "hi";
		x = 2;
	} else
		y = 3;

	# stmt for if and stmtlist for 'else'
	if ( y == 10 )
		z = 1;
	else {
		x = y * z;
		print "hello";
	}

	# dangling else
	if ( x ) if ( y ) x = 5; else y = 10;
}
