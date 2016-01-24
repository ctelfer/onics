# Test packet offset get and adjust, 0-length creation, pkt bitfield insert.
#

const START_OFF = 0;
const PAYLOAD_OFF = 1;
const TRAILER_OFF = 2;
const END_OFF = 3;

void dumptcp() {
	print "TCP segment starts at ",
 	      pkt_get_off(0, @tcp, 0, START_OFF);
	print "TCP header offset was ", 
 	      pkt_get_off(0, @tcp, 0, PAYLOAD_OFF);
	print "TCP trailer starts at ",
 	      pkt_get_off(0, @tcp, 0, TRAILER_OFF);
	print "TCP segment ends at ",
 	      pkt_get_off(0, @tcp, 0, END_OFF);
}


BEGIN {
	str payload;
	&payload = "HTTP GET / 1.0\n\n";

	len = 14 + 20 + 20;
	pkt_new_z(0, 2048);
	pkt_adj_off(0, @pkt, 0, TRAILER_OFF, len);
	pkt_adj_off(0, @pkt, 0, PAYLOAD_OFF, len);

	pdu_insert(pkt, @eth);
	pdu_insert(eth, @ip);
	pdu_insert(ip, @tcp);
	ip.saddr = 192.168.100.2;
	ip.daddr = 192.168.100.1;
	tcp.sport = 54321;
	tcp.dport = 8080;
	tcp.ack = 1;
	tcp.psh = 1;

	print "initial headers in packet";
	dumptcp();

	pkt_ins_u(0, str_addr(tcp.payload), str_len(payload));
	print "\nafter payload space insertion";
	dumptcp();

	pkt_adj_off(0, @tcp, 0, PAYLOAD_OFF, -str_len(payload));
	print "\nafter header offset adjustment";
	dumptcp();

	tcp.payload = payload;

	fix_dltype(0);
	fix_lens(0);
	fix_csums(0);
	send;
}
