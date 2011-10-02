
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


func true() {
	while (1) {
		return 1;
	}
}


?- 1 -? { nextrule; }

?- ip -? { 
	i = 1;
	x = @tcp{0};
	if ( true() ) {
		drop;
	}
	nextpkt;
}

?- ip -? { 
	i = 1;
	x = @tcp{0};
	if ( 1 and true() ) {
		drop;
	}
	nextpkt;
}

?- ip -? { 
	i = 1;
	x = @tcp{0,i};
	if ( 1 and true() ) {
		drop;
	}
	nextpkt;
}

?- ip -? { 
	i = 1;
	if ( @tcp{0,i} and true() ) {
		drop;
	}
	nextpkt;
}

