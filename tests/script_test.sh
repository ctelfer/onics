#!/bin/sh

IPATH=-PI../lib
export IPATH
TOUT=tmp
SCR=../scripts
DATA=data/scripts
RET=0


#
# $1 - Test name
# $2 - function
#
run_test() {
	echo "$1 -- ($2)"
	echo "------------------"
	$2 > $TOUT/$2.out 2>$TOUT/$2.err
	if [ $? -ne 0 ]
	then
		echo run-time error
		RET=1
	elif [ ! -f $DATA/$2.out ] &&
	     [ ! -f $DATA/$2.err ]
	then
		echo SKIPPED
	else
		if ! cmp $TOUT/$2.out $DATA/$2.out ||
		   ! cmp $TOUT/$2.err $DATA/$2.err
		then
			echo FAILED
			ERR=1
		else
			echo PASSED
		fi
	fi

	echo "------------------"
	echo
}


t_mkarp_nomods() {
	$SCR/mkarp
}

t_mkarp() {
	$SCR/mkarp "arp.sndpraddr = 1.2.3.4;"
}

t_mktcp_empty_nomods() {
	$SCR/mktcp
}

t_mktcp_empty() {
	$SCR/mktcp -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mktcp_stdin() {
	echo "Hello world!" | $SCR/mktcp - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mktcp_file() {
	$SCR/mktcp $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mkudp_empty_nomods() {
	$SCR/mkudp
}

t_mkudp_empty() {
	$SCR/mkudp -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkudp_stdin() {
	echo "Hello world!" | $SCR/mkudp - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkudp_file() {
	$SCR/mkudp $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkicmp_empty_nomods() {
	$SCR/mkicmp
}

t_mkicmp_empty() {
	$SCR/mkicmp -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"icmp.seq = 4444;"
}

t_mkicmp_stdin() {
	echo "Hello world!" | $SCR/mkicmp - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"icmp.seq = 4444;"
}

t_mkicmp_file() {
	$SCR/mkicmp $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip.daddr = 101.102.103.104;" \
		"icmp.seq = 4444;"
}

t_mktcp6_empty_nomods() {
	$SCR/mktcp6
}

t_mktcp6_empty() {
	$SCR/mktcp6 -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mktcp6_stdin() {
	echo "Hello world!" | $SCR/mktcp6 - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mktcp6_file() {
	$SCR/mktcp6 $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"tcp.psh = 1;" \
		"tcp.dport = 55555;"
}

t_mkudp6_empty_nomods() {
	$SCR/mkudp6
}

t_mkudp6_empty() {
	$SCR/mkudp6 -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkudp6_stdin() {
	echo "Hello world!" | $SCR/mkudp6 - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkudp6_file() {
	$SCR/mkudp6 $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"udp.cksum = 1;" \
		"udp.dport = 55555;"
}

t_mkicmp6_empty_nomods() {
	$SCR/mkicmp6
}

t_mkicmp6_empty() {
	$SCR/mkicmp6 -- \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"icmp6.echo.seq = 4444;"
}

t_mkicmp6_stdin() {
	echo "Hello world!" | $SCR/mkicmp6 - \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"icmp6.echo.seq = 4444;"
}

t_mkicmp6_file() {
	$SCR/mkicmp6 $DATA/testfile \
		"eth.src = 02:11:22:33:44:55;" \
		"ip6.daddr = fe80:eeee:dddd:cccc::1;" \
		"icmp6.echo.seq = 4444;"
}

run_test "ARP test" t_mkarp
run_test "ARP over IPv4 no modifications test" t_mkarp_nomods
run_test "TCP over IPv4 empty no modification test" t_mktcp_empty_nomods
run_test "TCP over IPv4 empty test" t_mktcp_empty
run_test "TCP over IPv4 stdin data test" t_mktcp_stdin
run_test "TCP over IPv4 file data test" t_mktcp_file
run_test "UDP over IPv4 empty no modification test" t_mkudp_empty_nomods
run_test "UDP over IPv4 empty test" t_mkudp_empty
run_test "UDP over IPv4 stdin data test" t_mkudp_stdin
run_test "UDP over IPv4 file data test" t_mkudp_file
run_test "ICMP empty no modification test" t_mkicmp_empty_nomods
run_test "ICMP empty test" t_mkicmp_empty
run_test "ICMP stdin data test" t_mkicmp_stdin
run_test "ICMP file data test" t_mkicmp_file
run_test "TCP over IPv6 empty no modification test" t_mktcp6_empty_nomods
run_test "TCP over IPv6 empty test" t_mktcp6_empty
run_test "TCP over IPv6 stdin data test" t_mktcp6_stdin
run_test "TCP over IPv6 file data test" t_mktcp6_file
run_test "UDP over IPv6 empty no modification test" t_mkudp6_empty_nomods
run_test "UDP over IPv6 empty test" t_mkudp6_empty
run_test "UDP over IPv6 stdin data test" t_mkudp6_stdin
run_test "UDP over IPv6 file data test" t_mkudp6_file
run_test "ICMPv6 empty no modification test" t_mkicmp6_empty_nomods
run_test "ICMPv6 empty test" t_mkicmp6_empty
run_test "ICMPv6 stdin data test" t_mkicmp6_stdin
run_test "ICMPv6 file data test" t_mkicmp6_file

exit $RET
