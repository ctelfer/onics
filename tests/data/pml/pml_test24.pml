# Multi-expression print statements
#
int ival = 0x12345678;
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

	print "0x", %x%ival, "\n";
	print ival, "\n";
	print "|", %-40u%ival, "|\n";
	print %o%ival, "\n";

	print %-12s%"string: ", s2[2,1], "\n";
	print %-12s%"binary: ", %b%s2[2,1], "\n";
	print %-12s%"octal: ", %o%s2[2,1], "\n";
	print %-12s%"decimal: ", %d%s2[2,1], "\n";
	print %-12s%"unsigned: ", %u%s2[2,1], "\n";
	print %-12s%"hex:", "0x", %-8x%s2[2,1], "\n";

	print %-12s%"val to ext:", "0x", %-8x%s2[4,1], "\n";
	y = sext(s2[4,1], 7);
	print %d%y, "\n";
	print %u%y, "\n";
}
