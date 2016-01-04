# Test walking headers indirectly by variable.
#

int P = 0;
{ 
  P = P + 1;
  print "Packet ", P;
  i = 1;
  while ( $(0,i)pdu.exists ) {
    print "    Header ", i, ": PRID = ", %04x%$(0, i)pdu.prid; 
    i = i + 1;
  } 
  drop;
}
