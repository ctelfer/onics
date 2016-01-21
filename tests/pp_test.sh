#!/bin/sh

TOUT=tmp
TBIN=bin
DATA=data/pp
RET=0

echo "---------------"
echo "Protocol parse test"
$TBIN/testpp < $DATA/pp_test.xpkt > $TOUT/pp_test.out 2> $TOUT/pp_test.err

if cmp $TOUT/pp_test.out $DATA/pp_test.out &&
   cmp $TOUT/pp_test.err $DATA/pp_test.err
then
	echo PASSED
else
	echo FAILED
	RET=1
fi
echo "---------------"
echo

echo "---------------"
echo "Packet buffer packet generation test"
$TBIN/testpkb > $TOUT/testpkb.out 2> $TOUT/testpkb.err

if cmp $TOUT/testpkb.out $DATA/testpkb.out &&
   cmp $TOUT/testpkb.err $DATA/testpkb.err
then
	echo PASSED
else
	echo FAILED
	RET=1
fi
echo "---------------"
echo

exit $RET
