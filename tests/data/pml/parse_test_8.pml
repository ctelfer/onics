# Complex binary expression tree
#
?- ((tcp.plen == ip.hlen) + (udp.plen - tcp.tlen)) * 
   ((ip6.error / ip.prid) << (icmp.index >> icmp.header)) %
   ((icmp6.payload ^ tcp.trailer) & (ip.df | tcp.syn)) -? { 
}
   
