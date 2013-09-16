# Byte string and masked string matching
#
# Need to test with mismatched lengths as well.
#
str value[16] = \x112233445566778899AABBCCDDEEFF00;

BEGIN {
	if (value =~ \x1122334455667788) {
		print "bad length match for byte string";
	} else {
		print "good length match fail for byte string";
	}

	if (value[0,8] =~ \x1122334455667788) {
		print "good byte match for byte string";
	} else {
		print "bad byte match for byte string";
	}

	if (value[2,8] =~ \x1122334455667788) {
		print "bad byte match for byte string offset";
	} else {
		print "good byte match fail for byte string offset";
	}

	if (value[6] =~ \x708090A0/\xF0F0F0F0) {
		print "bad length match for mask string";
	} else {
		print "good length match fail for mask string";
	}

	if (value[6,4] =~ \x708090A0/\xF0F0F0F0) {
		print "good match for mask string";
	} else {
		print "bad match fail for mask string";
	}

	if (value[8,4] =~ \x708090A0/\xF0F0F0F0) {
		print "bad match for mask string at wrong offset";
	} else {
		print "good match fail for mask string at wrong offset";
	}
}
