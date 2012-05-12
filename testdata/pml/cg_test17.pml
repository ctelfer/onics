#
# expressions as statements
#
func dummy(a, b, c) {
	return 2 * b + c << a;
}

 { fix_all_len(0); }

 { 3 + 5; }

 { 2 * 3 + tcp.sport; }

 { dummy(1, 2, 3); }
