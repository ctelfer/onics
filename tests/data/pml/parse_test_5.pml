# Control flow modification tests
#
BEGIN {
	i = 0;
	while (i < 5) {
		if (i == 3) {
			break;
		}
		if (i == 2) {
			continue;
		}
	}
}


int true() {
	while (1) {
		return 1;
	}
}


?- 1 -? { nextrule; }

?- ip -? { 
	i = 1;
	x = $(0)tcp;
	if ( true() ) {
		drop;
	}
	sendpkt;
}

?- ip -? { 
	i = 1;
	x = $(0)tcp;
	if ( 1 and true() ) {
		drop;
	}
	sendpkt;
}

?- ip -? { 
	i = 1;
	x = $(0,i)tcp;
	if ( 1 and true() ) {
		drop;
	}
	sendpkt;
}

?- ip -? { 
	i = 1;
	if ( $(0,i)tcp and true() ) {
		drop;
	}
	sendpkt;
}

