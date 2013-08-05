# TICK parsing
#

int T = 0;

TICK {
	T = T + 1; 
	if (T == 1000) {
		exit(0);
	}
}
