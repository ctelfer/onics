var foo = 0xdeadbeef12345678;
var bar = 0x1213141516171819;

BEGIN {
	if (mem[&foo, 8] == foo) {
		print "foo agrees\n";
	} else {
		print "error: foo does not agree\n";
	}

	if (mem[&bar, 8] == bar) {
		print "bar agrees\n";
	} else {
		print "error: bar does not agree\n";
	}

	if (mem[&foo+5,3] == 0x345678) {
		print "good: foo[5,3] == 0x345678\n";
	} else {
		print "error: foo[3,3] != 0x345678\n";
	}
}
