# Ethernet and IPv6 Address parsing
#
{
	eth.dst = ff:ff:ff:ff:ff:ff;
	eth.dst = 01:02:03:04:05:06;
	eth.dst = 9:8:7:6:5:4;
	ip6.saddr = ::;
	ip6.saddr = ::1;
	ip6.saddr = fe80::1;
	ip6.saddr = 1:2:3:4:5:6:7:8;
	ip6.saddr = 11:22:33:44:55:66:77:88;
	ip6.saddr = 111:222:333:444:555:666:777:888;
	ip6.saddr = 1111:2222:3333:4444:5555:6666:7777:8888;
	ip6.saddr = a:b:c:d:e:f:7:8;
	ip6.saddr = aa:bb:cc:dd:ee:ff:77:88;
	ip6.saddr = aaa:bbb:ccc:ddd:eee:fff:777:888;
	ip6.saddr = aaaa:bbbb:cccc:dddd:eeee:ffff:7777:8888;
	ip6.saddr = ::8888;
	ip6.saddr = 1111::8888;
	ip6.saddr = 1111:2222::8888;
	ip6.saddr = 1111:2222:3333::8888;
	ip6.saddr = 1111:2222:3333:4444::8888;
	ip6.saddr = 1111:2222:3333:4444:5555::8888;
	ip6.saddr = 1111:2222:3333:4444:5555:6666::8888;
	ip6.saddr = 1111::7777:8888;
	ip6.saddr = 1111::6666:7777:8888;
	ip6.saddr = 1111::5555:6666:7777:8888;
	ip6.saddr = 1111::4444:5555:6666:7777:8888;
	ip6.saddr = 1111::3333:4444:5555:6666:7777:8888;
	ip6.saddr = ::2222:3333:4444:5555:6666:7777:8888;
}
