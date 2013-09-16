# Test TICK with packets flowing: simple count
#
int T = 0;
int C = 0;

{ C = C + 1; drop; }
TICK {
	T = T + 1;
	if (T % 200 == 0) {
		print C, " packets seen so far";
	}
}
END { print C, " packets seen total"; } 

