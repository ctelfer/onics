# Global scalar variables
#
# drop, sendpkt, header match, global variables, constant initialization.
#
 
int n = 0;

?- tcp and (n < 1) -? { 
	n = 1; 
	sendpkt;
}

{ drop; }
