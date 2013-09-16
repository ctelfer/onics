# Test appinfo metadata manipulation
#
const APPINFO = 128;
const NBYTES  = 64;
{
  print "checking for tag";
  if (not meta_has(0, APPINFO)) {
    print "adding tag";
    meta_add_info(0, NBYTES/4);

    print "setting subtype";
    meta_wr16(0, APPINFO, 2, 0x1234);

    print "writing 1-byte values";
    i = 0;
    while (i < 16) {
      meta_wr8(0, APPINFO, 4 + i, i | 0x80);
      i = i + 1;
    }

    print "writing 2-byte values";
    while (i < 32) {
      meta_wr16(0, APPINFO, 4 + i, i | 0x8000);
      i = i + 2;
    }

    print "writing 4-byte values";
    while (i < 48) {
      meta_wr32(0, APPINFO, 4 + i, i | 0x80000000);
      i = i + 4;
    }
  }


  print "\nNow reading back data";
  print "subtype = ", %04x%meta_rd16(0, APPINFO, 2),;

  i = 0;
  while (i < NBYTES) {
    if (i % 16 == 0)
      print "\n\t",;
    print %02x%meta_rd8(0, APPINFO, 4 + i),;
    i = i + 1;
  }
  print "";
}
