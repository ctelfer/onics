# Packet fields and bit fields
#
?- eth.vlan0 and eth.vlan0.pri > 1 -? 
{ 
	drop; 
}

?- eth.vlan1 and eth.vlan1.vid & 0xF0F -? { 
	send; 
}
