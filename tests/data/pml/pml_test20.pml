# Memory indirection
#
str foo[8] = \xdeadbeef12345678;
str bar[8] = \x1213141516171819;
sref fp;
sref bp;

BEGIN {
	fp = &foo;
	if (fp == foo) {
		print "foo agrees\n";
	} else {
		print "error: foo does not agree\n";
	}

	bp = &bar;
	if (bp[0, 8] == bar) {
		print "bar agrees\n";
	} else {
		print "error: bar does not agree\n";
	}

	if (fp[5,3] == 0x345678) {
		print "good: fp[5,3] == 0x345678\n";
	} else {
		print "error: fp[3,3] != 0x345678\n";
	}
}
