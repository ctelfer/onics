# Multiple rules, drop, nexpkt, and protocol presence.
#
?- ip -? { drop; } 
?- ip6 -? { sendpkt; } 
