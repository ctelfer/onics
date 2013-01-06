#!/bin/sh

TOUT=tmp
TBIN=bin
SDIR=../scripts
BDIR=../bin
DATA=data/seq
RET=0

export PATH=$PATH:$BDIR

VERIFY="
	int nseq = 1;

	{ s = meta_get_seq(0);
	  if ( s != nseq )
		  print \"packet \", nseq, \" out of order (\", s, \"\\n\";
	  nseq = nseq + 1;
	  drop;
	}

	END { print nseq-1, \" packets total\\n\"; }
"

# $1 = num, $2 = name, $3 = seqarg, $4 = xseqarg
seqtest() {
	echo "---------------"
	echo "Sequence Test $1: $2"

	if [ "$3" = "NONE" ]
	then
		$SDIR/pxseq $4 < $DATA/seqin.xpkt | 
			$BDIR/pml -e "$VERIFY" > /dev/null 2>$TOUT/seq$1.err
	else
		$SDIR/peseq $3 < $DATA/seqin.xpkt | $SDIR/pxseq $4 | 
			$BDIR/pml -e "$VERIFY" > /dev/null 2>$TOUT/seq$1.err
	fi

	if [ $? -eq 0 ] 
	then
		if [ -f $DATA/seq$1.err ] 
		then
			if cmp $TOUT/seq$1.err $DATA/seq$1.err
			then
				echo PASSED
			else
				echo FAILED
				echo "   Output differs"
				RET=1
			fi
		else
			echo SKIPPED
		fi
	else
		echo FAILED
		echo "   Failed to run"
		RET=1
	fi
	echo "---------------"
	echo
}


seqtest 1 "Basic test" NONE ""
seqtest 2 "IP Frag ID test" "-c -ipid" "-c -ipid"
seqtest 3 "IP Frag ID + Eth dst test" "-c -ipid -edst" "-c -ipid -edst"
seqtest 4 "Eth dst test" "-c -edst" "-c -edst"
seqtest 5 "Eth src test" "-c -esrc" "-c -esrc"
seqtest 6 "IP dst test" "-c -ipdst" "-c -ipdst"
seqtest 7 "IP src test" "-c -ipsrc" "-c -ipsrc"
seqtest 8 "IPv6 Flowid" "-c -v6fid" "-c -v6fid"
seqtest 9 "TCP payload bytes 0-3" "-c -tpld 0,4" "-c -tpld 0,4"
seqtest 10 "UDP payload bytes 0-7" "-c -upld" "-c -upld"
seqtest 11 "ICMP payload bytes 4-5" "-c -ipld 4,2" "-c -ipld 4,2"
seqtest 12 "ICMPv6 payload bytes 4-5" "-c -i6pld 4,2" "-c -i6pld 4,2"
seqtest 13 "Big mix" \
	"-c -tpld -ipid -v6fid -edst" \
	"-c -tpld -ipid -v6fid -edst"

exit $RET
