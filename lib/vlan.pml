#
# VLAN Constants and utilities
#

const ETYPE_C_VLAN = 0x8100;
const ETYPE_S_VLAN = 0x88a8;

inline etype_is_vlan(int etype) { 
	etype == ETYPE_C_VLAN or etype == ETYPE_S_VLAN
}

inline vlan_present(int pnum)
{
	$(pnum)eth and etype_is_vlan($(pnum)eth[12,2])
}

void vlan_push(int pnum, int vid)
{
	if (not $(pnum)eth)
		return 0;
	pkt_ins_d(pnum, str_addr($(pnum)eth) + 12, 4);
	$(pnum)eth[12,4] = (ETYPE_C_VLAN << 16) | (vid & 0xFFFF);
	parse_update($(pnum)eth);
}

void vlan_pop(int pnum)
{
	if (not vlan_present(pnum))
		return 0;
	pkt_cut_u($(pnum)eth[12,4]);
}
