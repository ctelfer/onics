#!/bin/sh

ERR=0
OBIN=../bin
TOUT=tmp
PDIR=data/packets


# $1 - test number 
# $2 - infile|NONE|PROG_some_expression_here
# $3 - flags
# $4 - expected return (optional)
pml_test() { 
	FAIL=0
	if [ $# -gt 3 ]
	then
		EXPRET=$4
	else
		EXPRET=0
	fi
	echo "------------------"
	echo -n "PML execution test $1: "
	head -1 data/pml/pml_test$1.pml | sed -e 's/# *//'


	if [ "$2" = NONE ]
	then
		$OBIN/pml -f data/pml/pml_test$1.pml $3 > $TOUT/pml_test$1.out \
			2>$TOUT/pml_test$1.err
	elif echo $2 | grep '^PROG_' >/dev/null 2>&1
	then
		INPUT=`echo $2 | sed -e 's/^PROG_//'`
		eval "$INPUT | $OBIN/pml -f data/pml/pml_test$1.pml $3 > $TOUT/pml_test$1.out 2>$TOUT/pml_test$1.err"
	else
		$OBIN/pml -f data/pml/pml_test$1.pml $3 < $2 \
			> $TOUT/pml_test$1.out \
			2>$TOUT/pml_test$1.err
	fi

	STATUS=$?
	if [ $STATUS -ne $EXPRET ]
	then
		echo Error running program: exit code $STATUS expecting $EXPRET
		echo FAILED
		ERR=1
		FAIL=1
	elif [ ! -f data/pml/pml_test$1.out ] &&
	     [ ! -f data/pml/pml_test$1.err ]
	then
		echo SKIPPED
	else
		if ! cmp $TOUT/pml_test$1.out data/pml/pml_test$1.out || 
		   ! cmp $TOUT/pml_test$1.err data/pml/pml_test$1.err
		then
			echo FAILED
			ERR=1
			FAIL=1
		fi

		if [ $FAIL -eq 0 ]
		then
			echo PASSED
		fi
	fi


	echo "------------------"
	echo
}


pml_test 1 NONE -svvv
pml_test 2 $PDIR/onepkt.xpkt
pml_test 3 $PDIR/onev4onev6.xpkt
# 4 omitted for now
pml_test 5 NONE
pml_test 6 $PDIR/twoudp.xpkt
pml_test 7 $PDIR/onetcp.xpkt
pml_test 8 $PDIR/onepkt.xpkt
pml_test 9 NONE
pml_test 10 $PDIR/goodbad.xpkt
pml_test 11 $PDIR/sample.xpkt
pml_test 12 NONE -svvv
pml_test 13 NONE
pml_test 14 $PDIR/sample.xpkt
pml_test 15 NONE -svvv
pml_test 16 $PDIR/onetcp.xpkt
# 17 is code generation only
pml_test 18 NONE
pml_test 19 $PDIR/onepkt.xpkt
pml_test 20 NONE
pml_test 21 NONE
pml_test 22 NONE
pml_test 23 $PDIR/hellogoodbye.xpkt
pml_test 24 NONE
pml_test 25 $PDIR/onepkt.xpkt
pml_test 26 NONE
pml_test 27 NONE
pml_test 28 NONE
pml_test 29 NONE
pml_test 30 NONE
pml_test 31 NONE
pml_test 32 NONE
pml_test 33 NONE
pml_test 34 NONE
pml_test 35 NONE "" 1
pml_test 36 $PDIR/onepkt.xpkt
pml_test 37 $PDIR/onepkt.xpkt
pml_test 38 $PDIR/raw.xpkt
pml_test 39 NONE
pml_test 40 NONE
pml_test 41 PROG_"(cat $PDIR/onepkt.xpkt ; sleep 1 ; cat $PDIR/onev4onev6.xpkt)"
pml_test 42 $PDIR/arpreq.xpkt
pml_test 43 $PDIR/onev6pkt.xpkt
pml_test 44 NONE
pml_test 45 $PDIR/onepkt.xpkt
pml_test 46 $PDIR/onepkt.xpkt
pml_test 47 NONE
pml_test 48 $PDIR/onepkt.xpkt
pml_test 49 $PDIR/twoudp.xpkt
pml_test 50 $PDIR/twoudp.xpkt
pml_test 51 NONE
pml_test 52 $PDIR/exmix.xpkt
pml_test 53 NONE
pml_test 54 NONE

exit $ERR
