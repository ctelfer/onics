# Basic string references as variables
#

str astring[16] = "foo bar baz ook";

BEGIN {
	str r1;
	str r2;

	&r1 = astring;
	&r2 = r1[4,8];
	print r2;
}
