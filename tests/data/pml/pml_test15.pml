# Numeric intrinsics
#
BEGIN {
	x = 5;
	y = 11;
	z = log2(pop(y * y)); # pop(121) == 6, log2(6) == 2
	x = max(x, z);
}
