# Test pdu_insert() and pdu_delete() functions.
#

?- gre -? { 
  pdu_insert(gre, @mpls);
  mpls.label = 1234;
  fix_lens(0);
  fix_csums(0);
  send_no_free 0;

  pdu_delete(mpls);
  fix_lens(0);
  fix_csums(0);
  send;
}

?- eth -? {
  i = 0;
  pdu_insert($(i, 0)eth, @mpls);
  mpls.label = 4321;
  send_no_free i;

  pdu_delete($(i, 0)mpls);
  send i;
}
