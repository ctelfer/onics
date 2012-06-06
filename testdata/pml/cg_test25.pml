
{
  print "before\n";
  ts = meta_get_tstamp(0);
  sec = ts / 1000000000;
  nsec = ts % 1000000000;
  print "timestamp = ", %u:sec, " seconds and ", %u:nsec, " nanoseconds\n";
  print "pre-snap length = ", %d:meta_get_presnap(0), "\n";
  print "input port = ", %d:meta_get_inport(0), "\n";
  print "output port = ", %d:meta_get_outport(0), "\n";
  print "flow id = 0x", %x:meta_get_flowid(0), "\n";
  print "traffic class = 0x", %x:meta_get_class(0), "\n";
  print "\n";
}


{
  meta_set_tstamp(0, 1000000000);
  meta_set_presnap(0, 4096);
  meta_set_inport(0, 50);
  meta_set_outport(0, 51);
  meta_set_flowid(0, 0xdeadbeef);
  meta_set_class(0, 0x1010);
}


?- meta_get_outport(0) == 51 -? {
  print "after\n";
  ts = meta_get_tstamp(0);
  sec = ts / 1000000000;
  nsec = ts % 1000000000;
  print "timestamp = ", %u:sec, " seconds and ", %u:nsec, " nanoseconds\n";
  print "pre-snap length = ", %d:meta_get_presnap(0), "\n";
  print "input port = ", %d:meta_get_inport(0), "\n";
  print "output port = ", %d:meta_get_outport(0), "\n";
  print "flow id = 0x", %x:meta_get_flowid(0), "\n";
  print "traffic class = 0x", %x:meta_get_class(0), "\n";
}
