# Test TICK rules
#
int T=0; 
TICK { 
	T = T + 1;
	if (T % 10 == 0) { 
		print "10ms tick";
	} 
	if (T > 30) { 
		print "Timed out:  exiting";
		exit(0); 
	}
}
