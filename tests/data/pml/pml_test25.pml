# Metadata manipulation
#
{
  print "before";
  sec = meta_get_ts_sec(0);
  nsec = meta_get_ts_nsec(0);
  print "timestamp = ", %u%sec, " seconds and ", %u%nsec, " nanoseconds";
  print "pre-snap length = ", %d%meta_get_presnap(0);
  print "input port = ", %d%meta_get_inport(0);
  print "output port = ", %d%meta_get_outport(0);
  print "flow id = 0x", %x%meta_get_flowid(0);
  print "traffic class = 0x", %x%meta_get_class(0);
  print "";
}


{
  meta_set_ts(0, 1, 0);
  meta_set_presnap(0, 4096);
  meta_set_inport(0, 50);
  meta_set_outport(0, 51);
  meta_set_flowid(0, 0xdeadbeef);
  meta_set_class(0, 0x1010);
}


?- meta_get_outport(0) == 51 -? {
  print "after";
  sec = meta_get_ts_sec(0);
  nsec = meta_get_ts_nsec(0);
  print "timestamp = ", %u%sec, " seconds and ", %u%nsec, " nanoseconds";
  print "pre-snap length = ", %d%meta_get_presnap(0);
  print "input port = ", %d%meta_get_inport(0);
  print "output port = ", %d%meta_get_outport(0);
  print "flow id = 0x", %x%meta_get_flowid(0);
  print "traffic class = 0x", %x%meta_get_class(0);
}
