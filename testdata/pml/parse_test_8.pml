?- ((tcp.len == ip.hlen) + (udp.plen - tcp.tlen)) * 
   ((ip6.error / ip.prid) << (icmp.index >> header)) %
   ((icmp6.payload ^ tcp.trailer) & (ip.df | tcp.syn)) -? { 
}
   
