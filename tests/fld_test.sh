#!/bin/sh

TOUT=tmp
TBIN=bin
DATA=data/fld
RET=0

echo "---------------"
echo "Field Access Test"
$TBIN/testfld < $DATA/testfld.xpkt > $TOUT/testfld.out 2> $TOUT/testfld.err

if cmp $TOUT/testfld.out $DATA/testfld.out &&
   cmp $TOUT/testfld.err $DATA/testfld.err
then
	echo PASSED
else
	echo FAILED
	RET=1
fi
echo "---------------"
echo
exit $RET
