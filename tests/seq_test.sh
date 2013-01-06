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
seqtest 2 "IP Fragment ID test" "-c -ipid" "-c -ipid"

exit $RET
