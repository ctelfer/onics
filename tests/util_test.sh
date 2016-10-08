#!/bin/sh

TOUT=tmp
DATA=data/utils
BIN=../bin
RET=0


#
# $1 - Test name
# $2 - Test description
#
run_test() {
	echo "$2 -- ($1)"
	echo "------------------"
	$1 > $TOUT/$1.out 2>$TOUT/$1.err
	if [ $? -ne 0 ]
	then
		echo run-time error
		RET=1
	elif [ ! -f $DATA/$1.out ] &&
	     [ ! -f $DATA/$1.err ]
	then
		echo SKIPPED
	else
		if ! cmp $TOUT/$1.out $DATA/$1.out ||
		   ! cmp $TOUT/$1.err $DATA/$1.err
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


t_h2xpkt_immed() {
$BIN/h2xpkt - <<EOF
    000000:  00 00 00 6c 02 01 00 04 03 00 00 00 01 02 00 00  |...l............|
    000010:  57 2c 88 36 1a e3 7f c8                          |W,.6....|
    000018:  00 0d b9 23 f2 51 00 22 fa a7 69 90 08 00        |...#.Q."..i...|
    000026:  45 00 00 46 14 6f 40 00 40 11 76 33 c0 a8 00 04  |E..F.o@.@.v3....|
    000036:  47 3d a8 1b                                      |G=..|
    00003a:  99 71 04 aa 00 32 97 22                          |.q...2."|
    000042:  38 fe 2f 1d 0b 7f 3d 3e 75 f7 26 18 d7 c0 32 72  |8./...=>u.&...2r|
    000052:  2e 95 dc e1 50 f1 d3 21 11 41 f7 80 1f 00 00 00  |....P..!.A......|
    000062:  04 57 2c 88 3b 00 00 00 00 00                    |.W,.;.....|
EOF
}

t_h2xpkt_immed_nox() {
$BIN/h2xpkt -l eth - <<EOF
000000:  00 0d b9 23 f2 51 00 22 fa a7 69 90 08 00        |...#.Q."..i...|
00000e:  45 00 00 46 14 6f 40 00 40 11 76 33 c0 a8 00 04  |E..F.o@.@.v3....|
00001e:  47 3d a8 1b                                      |G=..|
000022:  99 71 04 aa 00 32 97 22                          |.q...2."|
00002a:  38 fe 2f 1d 0b 7f 3d 3e 75 f7 26 18 d7 c0 32 72  |8./...=>u.&...2r|
00003a:  2e 95 dc e1 50 f1 d3 21 11 41 f7 80 1f 00 00 00  |....P..!.A......|
00004a:  04 57 2c 88 3b 00 00 00 00 00                    |.W,.;.....|
EOF
}

t_h2xpkt_tcpdump() {
	tcpdump -nvvvvXXXXes 0 -r $DATA/udp.pcap 2>/dev/null | 
		grep '^[ 	]*0x' |
		$BIN/h2xpkt -l eth -
}

t_psort_basic() {
	$BIN/psort $DATA/psort_tcp.xpkt 
}

t_psort_tcpseq_rev() {
	$BIN/psort -r -k tcp.seqn $DATA/psort_tcp.xpkt 
}

t_psort_udp_2keys() {
	$BIN/psort -k udp.sport -k udp.dport $DATA/psort_udp.xpkt 
}

t_ipfrag_ipv4() {
	$BIN/ipfrag -m 576 -i 10 -d $DATA/tcp-fragtest.xpkt 
}

t_ipfrag_ipv6() {
	$BIN/ipfrag -6 -m 1280 -i 10 $DATA/tcp6-fragtest.xpkt 
}

t_ipfrag_combined() {
	cat $DATA/tcp-fragtest.xpkt $DATA/tcp6-fragtest.xpkt | \
		$BIN/ipfrag -46 -m 1280 -i 10
}

t_ipreasm_ipv4() {
	$BIN/ipreasm -4 $DATA/tcp-reasm.xpkt 
}

t_ipreasm_ipv6() {
	$BIN/ipreasm -6 $DATA/tcp6-reasm.xpkt 
}

t_ipreasm_combined() {
	cat $DATA/tcp-reasm.xpkt $DATA/tcp6-reasm.xpkt | $BIN/ipreasm -46
}


run_test t_h2xpkt_immed "h2xpkt -- basic from immediate data"
run_test t_h2xpkt_immed_nox "h2xpkt -- w/o xpkt header"
if which tcpdump > /dev/null 2>&1 
then
	run_test t_h2xpkt_tcpdump "h2xpkt -- tcpdump to xpkt via h2xpkt"
else
	echo Skipping tcpdump tests since I can\'t find tcpdump
fi
run_test t_psort_basic "psort -- sort by timestamp"
run_test t_psort_tcpseq_rev "psort -- reverse sort by TCP seqn"
run_test t_psort_udp_2keys "psort -- sort by src port then dst port"
run_test t_ipfrag_ipv4 "ipfrag -- IPv4, 576-byte MTU, set IP ID 10, set DF"
run_test t_ipfrag_ipv6 "ipfrag -- IPv6, 1280-byte MTU, set ID 10"
run_test t_ipfrag_combined "ipfrag -- IPv4+IPv6, 1280-byte MTU, set ID 10"
run_test t_ipreasm_ipv4 "ipreasm -- IPv4 basic reassembly"
run_test t_ipreasm_ipv6 "ipreasm -- IPv6 basic reassembly"
run_test t_ipreasm_combined "ipreasm -- combined IPv4+IPv6 reassembly"

exit $RET
