# Test fixing IPv6 lengths with options
#
void insert_hop_by_hop()
{
    pkt_ins_u(0, str_addr(ip6.header)+40, 8);
    ip6.header[40, 1] = ip6.nxthdr;
    ip6.header[41, 7] = \x00000000000000;
    ip6.nxthdr = 0;
    fix_lens(0);
}

?- ip6 and ip6.hlen <= 40 -? { insert_hop_by_hop(); }
