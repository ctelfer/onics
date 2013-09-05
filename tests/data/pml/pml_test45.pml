# Metadata manipulation with generic functions
#
const TS=1;
const SNAP=2;
const INIF=3;
const OUTIF=4;
const FLOW=5;
const CLASS=6;
const SEQ=7;
const PARSE=8;
const INFO=128;
{
  print "before\n";

  print "meta_has(0, TS)=", meta_has(0, TS), "\n";
  if (meta_has(0, TS)) {
	  sec = meta_get_ts_sec(0);
	  nsec = meta_get_ts_nsec(0);
	  print "\ttimestamp = ", %u%sec, " seconds and ", %u%nsec, " nanoseconds\n";
  }

  print "meta_has(0, SNAP)=", meta_has(0, SNAP), "\n";
  if (meta_has(0, SNAP)) 
	  print "\tpre-snap length = ", %d%meta_get_presnap(0), "\n";

  print "meta_has(0, INIF)=", meta_has(0, INIF), "\n";
  if (meta_has(0, INIF))
	  print "\tinput port = ", %d%meta_get_inport(0), "\n";

  print "meta_has(0, OUTIF)=", meta_has(0, OUTIF), "\n";
  if (meta_has(0, OUTIF))
	  print "\toutput port = ", %d%meta_get_outport(0), "\n";

  print "meta_has(0, FLOW)=", meta_has(0, FLOW), "\n";
  if (meta_has(0, FLOW))
	  print "\tflow id = 0x", %x%meta_get_flowid(0), "\n";

  print "meta_has(0, CLASS)=", meta_has(0, CLASS), "\n";
  if (meta_has(0, CLASS))
	  print "\ttraffic class = 0x", %x%meta_get_class(0), "\n";

  print "meta_has(0, SEQ)=", meta_has(0, SEQ), "\n";
  if (meta_has(0, SEQ))
	  print "\tsequence number = ", %d%meta_get_seq(0), "\n";

  print "meta_has(0, PARSE)=", meta_has(0, PARSE), "\n";
  print "\n";
}


{
  if (not meta_has(0, TS)) {
	print "adding timestamp\n";
	meta_add(0, TS);
  }
  meta_wr32(0, TS, 4, 1);
  meta_wr32(0, TS, 8, 2);

  if (not meta_has(0, SNAP)) {
	print "adding snap info\n";
	meta_add(0, SNAP);
  }
  meta_wr32(0, SNAP, 4, 4096);

  if (not meta_has(0, INIF)) {
	print "adding inport\n";
  	meta_add(0, INIF);
  }
  meta_wr16(0, INIF, 2, 50);

  if (not meta_has(0, OUTIF)) {
	print "adding outport\n";
	meta_add(0, OUTIF);
  }
  meta_wr16(0, OUTIF, 2, 51);

  if (not meta_has(0, FLOW)) {
	print "adding flow\n";
  	meta_add(0, FLOW);
  }
  meta_wr32(0, FLOW, 8, 0xdeadbeef);

  if (not meta_has(0, CLASS)) {
	print "adding class\n";
  	meta_add(0, CLASS);
  }
  meta_wr32(0, CLASS, 8, 0x1010);

  if (not meta_has(0, SEQ)) {
	print "adding seq\n";
	meta_add(0, SEQ);
  }
  meta_wr32(0, SEQ, 8, 1234);

  print "\n";
}


?- meta_get_outport(0) == 51 -? {
  print "after\n";
  sec = meta_get_ts_sec(0);
  nsec = meta_get_ts_nsec(0);
  print "timestamp = ", %u%sec, " seconds and ", %u%nsec, " nanoseconds\n";
  print "pre-snap length = ", %d%meta_get_presnap(0), "\n";
  print "input port = ", %d%meta_get_inport(0), "\n";
  print "output port = ", %d%meta_get_outport(0), "\n";
  print "flow id = 0x", %x%meta_get_flowid(0), "\n";
  print "traffic class = 0x", %x%meta_get_class(0), "\n";
  print "sequence number = ", %d%meta_get_seq(0), "\n";
}
