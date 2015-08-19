# Checksum test with varying sized TCP packets
#
import "../lib/std.pml";

str payload[202];

BEGIN {
	i = 0;
	while (i < str_len(payload)) {
		payload[i, 1] = i;
		i = i + 1;
	}

	mk_tcp();
	pkt_splice(tcp.payload, payload);
	fix_lens(0);
	fix_csums(0);
	send_no_free 0;

	pkt_cut_d(tcp.payload[str_len(tcp.payload) - 1, 1]);
	fix_lens(0);
	fix_csums(0);
	send_no_free 0;

	pkt_cut_d(tcp.payload[str_len(tcp.payload) - 1, 1]);
	fix_lens(0);
	fix_csums(0);
	send_no_free 0;

	pkt_cut_d(tcp.payload[str_len(tcp.payload) - 1, 1]);
	fix_lens(0);
	fix_csums(0);
	send_no_free 0;

	pkt_splice(tcp.payload, payload[0,45]);
	fix_lens(0);
	fix_csums(0);
	send;
}

