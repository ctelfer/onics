# Insert TCP timestamp (high field number)
#

void tcp_ts_insert(int val, int echo)
{
    int off;
    str ts;

    off = str_addr(tcp.payload);
    pkt_ins_u(0, off, 12);
    &ts = str_mkref(1, 0, off, 12);
    ts[0,2] = \x080a;
    ts[10,2] = 0;
    fix_lens(0);
    pkt_parse(0);
    tcp.ts.val = val;
    tcp.ts.echo = echo;
    fix_csums(0);
}

?- tcp and not tcp.ts -? { tcp_ts_insert(0xaaaaaaaa, 0xbbbbbbbb); }
