# Existence test when no packet present
#
BEGIN {
	if ( not pkt )
		print "There is no packet.";
	else
		print "There is a packet when there shouldn't be!";
	
	if ( not pkt.exists )
		print "There is still no packet.";
	else
		print "There is a packet when there shouldnt' be! (.exists).";

	if ( not $(1)pkt ) 
		print "Packet 1 doesn't exist either.";
	else
		print "There is a packet when there shouldn't be! $(1)";

	if ( not $(1)pkt.exists )
		print "Packet 1 doesn't exist again.";
	else
		print "There is a packet when there shouldn't be! $(1).exists";
}

{ 
	if ( not pkt )
		print "There is no packet when there should be!";
	else
		print "Got a packet when we should.";

	if ( not pkt.exists )
		print "There is no packet when there should be! (.exists)";
	else
		print "Got a packet when we should. (.exists)";

	if ( not $(1)pkt )
		print "Packet 1 doesn't when packet 0 does.";
	else
		print "There is a packet 1 wth packet 0! $(1)";

	if ( not $(1)pkt.exists )
		print "Packet 1 doesn't exist when packet 0 does.";
	else
		print "There is a packet 1 with packet 0! $(1).exists";
}
