inline flowid() { meta_get_flowid(0) }
int pn;
{ pn = pn + 1; }
?- flowid() > 0 -? { print "Packet ", pn, " has flow id ", flowid(); }
