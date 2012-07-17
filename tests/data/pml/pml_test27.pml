# Break/Continue test 2
#
BEGIN {
	i = 1;
	k = 1;
	while (i < 7) {
		j = i + 1;
		while (j % i != 0) {
			if (j == i + 1) {
				j = j + 1;
				continue;
			} 
			print "(i,j) = (", i, ",", j, ")\n";
			j = j + k;
			k = k + 1;
			if (j > 1000) {
				break;
			}
		}
		print "(i,j,k) = (", i, ",", j, ",", k, ")\n";
		i = i + 1;
		if (k > 50) {
		 	k = 1;
			continue;
		}
		print "keeping k\n";
	}
	
}
