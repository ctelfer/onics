# Packet enqueue/dequeue on lists.
#
BEGIN { print "There are ", pkt_nlists(), " packet lists"; }

{ pkt_enq(0, 0); }

END {
	if ( pkt_lempty(0) )
		print "Packet list 0 is empty";
	else
		print "Packet list 0 is not empty";

	if ( pkt_lempty(1) )
		print "Pakcet list 1 is empty";
	else
		print "Packet list 1 is not empty";

	pkt_deq(0, 0);
	while ( pkt ) {
		send 0;
		pkt_deq(0, 0);
	}
}
