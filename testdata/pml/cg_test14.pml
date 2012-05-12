var n = 0;
?- tcp and (n < 1) -? { n = 1; nextpkt; }
{ drop; }
