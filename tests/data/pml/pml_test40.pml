# Test TICK rules
#
int T=0; 
TICK { 
	T = T + 1;
	if (T % 10 == 0) { 
		print "10ms tick\n";
	} 
	if (T > 30) { 
		print "Timed out:  exiting\n";
		exit(0); 
	}
}
