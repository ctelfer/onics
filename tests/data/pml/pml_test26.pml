# Continue loop test
#
BEGIN {
	i = 0;
	while (i < 5) {
		if (i == 0) {
			i = i + 1;
			continue;
		}
		print "i = ", i, "\n";
		i = i + 1;
	}
}
