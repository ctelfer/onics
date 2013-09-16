# Memory indirection
#
str foo[8] = \xdeadbeef12345678;
str bar[8] = \x1213141516171819;
str fp;
str bp;

BEGIN {
	&fp = &foo;
	if (fp == foo) {
		print "foo agrees";
	} else {
		print "error: foo does not agree";
	}

	&bp = &bar;
	if (bp[0, 8] == bar) {
		print "bar agrees";
	} else {
		print "error: bar does not agree";
	}

	if (fp[5,3] == 0x345678) {
		print "good: fp[5,3] == 0x345678";
	} else {
		print "error: fp[3,3] != 0x345678";
	}
}
