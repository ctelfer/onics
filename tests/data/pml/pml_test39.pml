# String comparison tests
#

str s1[16] = "foo bar baz boo "; 
str s2[16] = "foo bar baz boo "; 
str s3[16] = "foo bar and sie "; 
str s4[4]  = "foo "; 
str sr;

BEGIN {
	pkt_new(0, 16);
	pkt.payload = "foo bar baz boo "; 
	pkt_new(1, 16);
	$(1)pkt.payload = "foo bar baz sie "; 
	pkt_new(2, 4);
	$(2)pkt.payload = "foo "; 

	#
	# string match against literal string
	#
	if (s1 =~ "foo bar baz boo ") { 
		print "SUCCESS literal string match"; 
	} else { 
		print "ERROR literal string mismatch"; 
	}

	if (s1 !~ "foo bar baz boo ") { 
		print "ERROR literal string not-match error"; 
	} else { 
		print "SUCCESS literal string not-match"; 
	}

	if (s1 =~ "foo bye and sie ") { 
		print "ERROR literal string fail match (eqlen) "; 
	} else { 
		print "SUCCESS literal string fail match (eqlen) "; 
	}

	if (s1 !~ "foo bye and sie ") { 
		print "SUCCESS literal string fail not-match (eqlen) "; 
	} else { 
		print "ERROR literal string fail not-match (eqlen) "; 
	}

	if (s1 =~ "foo ") { 
		print "ERROR literal string fail match (eqlen) "; 
	} else { 
		print "SUCCESS literal string fail match (eqlen) "; 
	}

	if (s1 !~ "foo ") { 
		print "SUCCESS literal string fail not-match (neqlen) "; 
	} else { 
		print "ERROR literal string fail not-match (neqlen) "; 
	}


	#
	# string eq against literal string
	#
	if (s1 == "foo bar baz boo ") { 
		print "SUCCESS literal string eq"; 
	} else { 
		print "ERROR literal string eq"; 
	}

	if (s1 != "foo bar baz boo ") { 
		print "ERROR literal string not eq error"; 
	} else { 
		print "SUCCESS literal string not-eq"; 
	}

	if (s1 == "foo bye and sie ") {
		print "ERROR literal string eq (eqlen) "; 
	} else { 
		print "SUCCESS literal string eq (eqlen) "; 
	}

	if (s1 != "foo bye and sie ") { 
		print "SUCCESS literal string fail not-eq (eqlen) "; 
	} else { 
		print "ERROR literal string fail not-eq (eqlen) "; 
	}

	if (s1 == "foo ") { 
		print "ERROR literal string fail eq (eqlen) "; 
	} else { 
		print "SUCCESS literal string fail eq (eqlen) "; 
	}

	if (s1 != "foo ") { 
		print "SUCCESS literal string fail not-eq (neqlen) "; 
	} else { 
		print "ERROR literal string fail not-eq (neqlen) "; 
	}


	#
	# string match against literal byte string
	# 
	if (s1 =~ \x666f6f206261722062617a20626f6f20) {
		print "SUCCESS literal byte string match"; 
	} else { 
		print "ERROR literal byte string mismatch"; 
	}

	if (s1 !~ \x666f6f206261722062617a20626f6f20) {
		print "ERROR literal byte string not-match error"; 
	} else { 
		print "SUCCESS literal byte string not-match"; 
	}

	if (s1 =~ \x666f6f2062617220616e642073696520) {
		print "ERROR literal byte string fail match (eqlen) "; 
	} else { 
		print "SUCCESS literal byte string fail match (eqlen) "; 
	}

	if (s1 !~ \x666f6f2062617220616e642073696520) {
		print "SUCCESS literal byte string fail not-match (eqlen) ";
	} else { 
		print "ERROR literal byte string fail not-match (eqlen) ";
	}

	if (s1 =~ \x666f6f20) {
		print "ERROR literal byte string fail match (eqlen) ";
	} else { 
		print "SUCCESS literal byte string fail match (eqlen) ";
	}

	if (s1 !~ \x666f6f20) {
		print "SUCCESS literal byte string fail not-match (neqlen) ";
	} else { 
		print "ERROR literal byte string fail not-match (neqlen) ";
	}



	#
	# string eq against literal byte string
	#
	if (s1 == \x666f6f206261722062617a20626f6f20) {
		print "SUCCESS literal byte string match"; 
	} else { 
		print "ERROR literal byte string mismatch"; 
	}

	if (s1 != \x666f6f206261722062617a20626f6f20) {
		print "ERROR literal byte string not-match error"; 
	} else { 
		print "SUCCESS literal byte string not-match"; 
	}

	if (s1 == x666f6f2062617220616e642073696520) {
		print "ERROR literal byte string fail match (eqlen) "; 
	} else { 
		print "SUCCESS literal byte string fail match (eqlen) "; 
	}

	if (s1 != x666f6f2062617220616e642073696520) {
		print "SUCCESS literal byte string fail not-match (eqlen) ";
	} else { 
		print "ERROR literal byte string fail not-match (eqlen) ";
	}

	if (s1 == \x666f6f20) {
		print "ERROR literal byte string fail match (eqlen) ";
	} else { 
		print "SUCCESS literal byte string fail match (eqlen) ";
	}

	if (s1 != \x666f6f20) {
		print "SUCCESS literal byte string fail not-match (neqlen) ";
	} else { 
		print "ERROR literal byte string fail not-match (neqlen) ";
	}


	#
	# string eq against string variable 
	#
	if (s1 == s2) { 
		print "SUCCESS string variable eq"; 
	} else { 
		print "ERROR string variable eq"; 
	}

	if (s1 != s2) { 
		print "ERROR string variable not-eq error"; 
	} else { 
		print "SUCCESS string variable not-eq"; 
	}

	if (s1 == s3) {
		print "ERROR string variable eq (eqlen) "; 
	} else { 
		print "SUCCESS string variable eq (eqlen) "; 
	}

	if (s1 != s3) { 
		print "SUCCESS string variable fail not-eq (eqlen) "; 
	} else { 
		print "ERROR string variable fail not-eq (eqlen) "; 
	}

	if (s1 == "foo ") { 
		print "ERROR string variable fail eq (eqlen) "; 
	} else { 
		print "SUCCESS string variable fail eq (eqlen) "; 
	}

	if (s1 != "foo ") { 
		print "SUCCESS string variable fail not-eq (neqlen) "; 
	} else { 
		print "ERROR string variable fail not-eq (neqlen) "; 
	}


	#
	# string eq against string reference
	#
	&sr = &s2;
	if (s1 == sr) { 
		print "SUCCESS string reference eq"; 
	} else { 
		print "ERROR string reference eq"; 
	}

	if (s1 != sr) { 
		print "ERROR string reference not-eq error"; 
	} else { 
		print "SUCCESS string reference not-eq"; 
	}

	&sr = &s3;
	if (s1 == sr) {
		print "ERROR string reference eq (eqlen) "; 
	} else { 
		print "SUCCESS string reference eq (eqlen) "; 
	}

	if (s1 != sr) { 
		print "SUCCESS string reference fail not-eq (eqlen) "; 
	} else { 
		print "ERROR string reference fail not-eq (eqlen) "; 
	}

	&sr = &s4;
	if (s1 == sr) { 
		print "ERROR string reference fail eq (eqlen) "; 
	} else { 
		print "SUCCESS string reference fail eq (eqlen) "; 
	}

	if (s1 != sr) { 
		print "SUCCESS string reference fail not-eq (neqlen) "; 
	} else { 
		print "ERROR string reference fail not-eq (neqlen) "; 
	}


	#
	# string eq against packet payload
	#
	if (s1 == pkt.payload) { 
		print "SUCCESS packet payload eq"; 
	} else { 
		print "ERROR packet payload eq"; 
	}

	if (s1 != pkt.payload) { 
		print "ERROR packet payload not-eq error"; 
	} else { 
		print "SUCCESS packet payload not-eq"; 
	}

	if (s1 == $(1)pkt.payload) {
		print "ERROR packet payload eq (eqlen) "; 
	} else { 
		print "SUCCESS packet payload eq (eqlen) "; 
	}

	if (s1 != $(1)pkt.payload) {
		print "SUCCESS packet payload fail not-eq (eqlen) "; 
	} else { 
		print "ERROR packet payload fail not-eq (eqlen) "; 
	}

	if (s1 == $(2)pkt.payload) { 
		print "ERROR packet payload fail eq (eqlen) "; 
	} else { 
		print "SUCCESS packet payload fail eq (eqlen) "; 
	}

	if (s1 != $(2)pkt.payload) {
		print "SUCCESS packet payload fail not-eq (neqlen) "; 
	} else { 
		print "ERROR packet payload fail not-eq (neqlen) "; 
	}

	drop 0;
	drop 1;
	drop 2;
}
