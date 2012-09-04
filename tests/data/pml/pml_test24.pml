# Multi-expression print statements
#
int s = 0x123456789ABCDEF0;
str s2[20] = \x00112233aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

inline sext(int v, int b) { v | -(v & (1 << b)) }

BEGIN { 
	x = 5;
	print "hello ", "world!\n";

	print "hello world: ", x, "\n";

	print "|", %-32s%"hello world", "|\n";
	print "|", %32s%"hello world", "|\n";
	print "|", %32hex%"hello world", "|\n";
	print "|", %-32hex%"hello world", "|\n";

	print s, "\n";
	print "|", %-40u%s, "|\n";
	print %o%s, "\n";

	print %-12s%"string: ", s2[2,1], "\n";
	print %-12s%"binary: ", %b%s2[2,1], "\n";
	print %-12s%"octal: ", %o%s2[2,1], "\n";
	print %-12s%"decimal: ", %d%s2[2,1], "\n";
	print %-12s%"unsigned: ", %u%s2[2,1], "\n";
	print %-12s%"hex:", "0x", %-8x%s2[2,1], "\n";

	y = sext(s2[4,1], 7);
	print %d%y, "\n";
	print %u%y, "\n";
}
