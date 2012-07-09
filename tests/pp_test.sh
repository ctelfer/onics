#!/bin/sh

TOUT=tmp
TBIN=bin
DATA=data/pp

echo "---------------"
echo "Protocol parse test"
$TBIN/testpp < $DATA/pp_test.xpkt > $TOUT/pp_test.out 2> $TOUT/pp_test.err

if cmp $TOUT/pp_test.out $DATA/pp_test.out &&
   cmp $TOUT/pp_test.err $DATA/pp_test.err
then
	echo PASSED
else
	echo FAILED
fi
echo "---------------"
echo
