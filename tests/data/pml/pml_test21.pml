# Byte string and masked string matching
#
# Need to test with mismatched lengths as well.
#
blob value[16] = \x112233445566778899AABBCCDDEEFF00;

BEGIN {
	if (value =~ \x1122334455667788) {
		print "bad length match for byte string\n";
	} else {
		print "good length match fail for byte string\n";
	}

	if (value[0,8] =~ \x1122334455667788) {
		print "good byte match for byte string\n";
	} else {
		print "bad byte match for byte string\n";
	}

	if (value[2,8] =~ \x1122334455667788) {
		print "bad byte match for byte string offset\n";
	} else {
		print "good byte match fail for byte string offset\n";
	}

	if (value[6] =~ \x708090A0/\xF0F0F0F0) {
		print "bad length match for mask string\n";
	} else {
		print "good length match fail for mask string\n";
	}

	if (value[6,4] =~ \x708090A0/\xF0F0F0F0) {
		print "good match for mask string\n";
	} else {
		print "bad match fail for mask string\n";
	}

	if (value[8,4] =~ \x708090A0/\xF0F0F0F0) {
		print "bad match for mask string at wrong offset\n";
	} else {
		print "good match fail for mask string at wrong offset\n";
	}
}
