# Packet field assignments
#
# fix lengths, (because ip[3,2] clobbers it) fix checksums, local vars,
# packet fields, truncation of scalars,
#
?- tcp -? { 
	ip[3,2] = 0xf00ba4;
	x = 2;
	ip.daddr[x] = \xbbaa;
	fix_lens(0);
	fix_csums(0);
}
