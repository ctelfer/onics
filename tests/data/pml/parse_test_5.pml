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
	x = $(1)tcp;
	if ( true() ) {
		drop;
	}
	send;
}

?- ip -? { 
	i = 1;
	x = $(2)tcp;
	if ( 1 and true() ) {
		drop;
	}
	send;
}

?- ip -? { 
	i = 1;
	x = $(3,i)tcp;
	if ( 1 and true() ) {
		drop;
	}
	send;
}

?- ip -? { 
	i = 1;
	if ( $(4,i)tcp and true() ) {
		drop;
	}
	send;
}

