# Test print statements with trailing commas.
#
int x;
str text[] = "a text string";
str ipa[] = 192.168.0.2;
str ip6a[] = ffff:eeee::1;
str etha[] = aa:bb:cc:dd:ee:ff;
BEGIN {
	x = 0xFFFFFFFF;
	print "First without commas:";
	print %d%x;
	print %u%x;
	print %x%x;
	print text;
	print %ip%ipa;
	print %ip6%ip6a;
	print %eth%etha;
	print "\n";
	print "Now without commas:";
	print %d%x,;
	print %u%x,;
	print %x%x,;
	print text,;
	print %ip%ipa,;
	print %ip6%ip6a,;
	print %eth%etha,;
	print "\n";
}
