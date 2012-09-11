# Basic string references as variables
#

str astring[16] = "foo bar baz ook";

BEGIN {
	sref r1;
	sref r2;

	r1 = &astring;
	r2 = &r1[4,8];
	print r2, "\n";
}
