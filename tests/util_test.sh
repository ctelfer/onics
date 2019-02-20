#!/bin/sh

TOUT=tmp
DATA=data/utils
BIN=../bin
ERR=0


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
		ERR=1
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

t_ipreasm_ipv6_opts() {
	$BIN/ipfrag -m 1500 -6 < $DATA/udp6opt.xpkt | $BIN/ipreasm -6 
}

t_nftrk_psplit_basic() {
	mkdir -p $TOUT/t_nftrk_psplit_basic_flows
	rm -f $TOUT/t_nftrk_psplit_basic_flows/*
	$BIN/nftrk -q $DATA/flows.xpkt | 
		$BIN/psplit -r -p $TOUT/t_nftrk_psplit_basic_flows/flow
	echo Flow files
	ls $TOUT/t_nftrk_psplit_basic_flows
	for f in `(cd $TOUT/t_nftrk_psplit_basic_flows; ls)`; do 
		if [ -f $DATA/t_nftrk_psplit_basic/$f ] ; then
			echo comparing $f
			cmp $TOUT/t_nftrk_psplit_basic_flows/$f \
			    $DATA/t_nftrk_psplit_basic/$f
		else
			echo Unable to find $DATA/t_nftrk_psplit_basic/$f
		fi
	done
}

#
# For pmerge tests the following traces are used:
#  * t_pmerge_128.xpkt - 8 128-byte tcp packets w/ timestamps 5, 10, 15, .. 40
#  * t_pmerge_256.xpkt - 4 256-byte tcp packets w/ timestamps 6, 11, 16, 21
#  * t_pmerge_512.xpkt - 2 512-byte tcp packets w/ timestamps 7, 12
#  * t_pmerge_512_x4.xpkt - 4 512-byte tcp packets w/ timestamps 8, 13, 18, 23
#

t_pmerge_rr() {
	$BIN/pmerge -R $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512.xpkt |
		pml -e '
		str esizes[] = \x0102040102040102010201010101;
		int x;
		{
			if (esizes[x,1]*128 != pkt.plen) {
				print "packet ", x, " has length ", pkt.plen;
				exit(1);
			}
			x = x + 1;
			drop;
		}
		'
}

t_pmerge_rr_c() {
	$BIN/pmerge -Rc -n 12 $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512.xpkt |
		pml -e '
		str esizes[] = \x010204010204010204010204;
		int x;
		{
			if (esizes[x,1]*128 != pkt.plen) {
				print "packet ", x, " has length ", pkt.plen;
				exit(1);
			}
			x = x + 1;
			drop;
		}
		'
}

t_pmerge_pkts_c() {
	$BIN/pmerge -Pc -n 28 $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512.xpkt |
		pml -e '
		int n128;
		int n256;
		int n512;
		int x;
		{
			if (pkt.plen == 128) {
				n128 = n128 + 1;
			} else if (pkt.plen == 256) {
				n256 = n256 + 1;
			} else if (pkt.plen == 512) {
				n512 = n512 + 1;
			}
			drop;
		}
		END {
			print "Expected 16 128-byte packets. Got ", n128;
			print "Expected  8 256-byte packets. Got ", n256;
			print "Expected  4 512-byte packets. Got ", n512;
			if (n128 != 16 or n256 != 8 or n512 != 4) {
				print "FAIL";
				exit(1);
			}
		}
		'
}

t_pmerge_bytes_c() {
	$BIN/pmerge -Pc -n 28 $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512.xpkt |
		pml -e '
		int n128;
		int n256;
		int n512;
		int x;
		{
			if (pkt.plen == 128) {
				n128 = n128 + 1;
			} else if (pkt.plen == 256) {
				n256 = n256 + 1;
			} else if (pkt.plen == 512) {
				n512 = n512 + 1;
			}
			drop;
		}
		END {
			print "Expected 16 128-byte packets. Got ", n128;
			print "Expected  8 256-byte packets. Got ", n256;
			print "Expected  4 512-byte packets. Got ", n512;
			if (n128 != 16 or n256 != 8 or n512 != 4) {
				print "FAIL";
				exit(1);
			}
		}
		'
}

t_pmerge_bytes_c2() {
	$BIN/pmerge -Bc -n 1000 $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512_x4.xpkt |
		pml -e '
		int n128;
		int n256;
		int n512;
		int x;
		{
			if (pkt.plen == 128) {
				n128 = n128 + pkt.plen;
			} else if (pkt.plen == 256) {
				n256 = n256 + pkt.plen;
			} else if (pkt.plen == 512) {
				n512 = n512 + pkt.plen;
			}
			drop;
		}
		END {
			print "Got ", n128, " bytes of 128-byte packets.";
			print "Got ", n256, " bytes of 256-byte packets.";
			print "Got ", n512, " bytes of 512-byte packets.";

			# if difference is > 2%: fail
			diff = n512 - (n128 + n256);
			if (diff < 0) {
				diff = -diff;
			}
			diff = diff / 100;
			print "Difference is ~", diff, "%";
			if (diff > 2) {
				print "FAIL";
				exit(1);
			}
		}
		'
}

t_pmerge_ts() {
	$BIN/pmerge -T $DATA/t_pmerge_128.xpkt $DATA/t_pmerge_256.xpkt \
		$DATA/t_pmerge_512.xpkt |
		pml -e '
		int min;
		int x;
		{ 
			x = x + 1;
			ts = meta_get_ts_sec(0);
			if (ts < min) {
				print "packet ", x, 
				      " is out of order by timestamp";
				exit(1);
			}
			min = ts;
			drop;
		}
		'
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
run_test t_ipreasm_ipv6_opts "ipreasm -- IPv6 with hop-by-hop options"
run_test t_nftrk_psplit_basic "nftrk/psplit -- Basic flow track + split"
run_test t_pmerge_rr "pmerge -- round robin"
run_test t_pmerge_rr_c "pmerge -- round robin, continuous"
run_test t_pmerge_pkts_c "pmerge -- proportional by # of packets, continuous"
run_test t_pmerge_bytes_c "pmerge -- proportional by # of bytes, continuous"
run_test t_pmerge_bytes_c2 "pmerge -- proportional by # of bytes, uneven traces"
run_test t_pmerge_ts "pmerge -- merge by timestamp"

exit $ERR
