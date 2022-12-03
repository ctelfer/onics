#!/bin/sh

TOUT=tmp
BIN=../bin
DATA=data/tcpcarve
SCR=../scripts
RET=0

echo "---------------"
echo "TCP Carve Test"
$SCR/tcpsess -c $DATA/get.http -s $DATA/onics.html |
	$BIN/tcpcarve -p "$TOUT/data." \
	> $TOUT/tcpcarve-test1.out 2>$TOUT/tcpcarve-test1.err

if [ $? -ne 0 ] ; then
	echo Error running tcpcarve
	echo FAILED
	RET=1
elif [ ! -f $TOUT/data.0000.c2s -o \
       ! -f $TOUT/data.0001.s2c -o \
       -x $TOUT/data.0002.c2s -o \
       -x $TOUT/data.0002.s2c ]; then
	echo Unexpected data files: expected $TOUT/data.0.c2s and $TOUT/data.1.s2c
	echo FAILED
	RET=1
elif ! cmp $TOUT/tcpcarve-test1.out $DATA/tcpcarve-test1.out ||
     ! cmp $TOUT/tcpcarve-test1.err $DATA/tcpcarve-test1.err
then
	echo Output from tcpcarve doesn\'t match
	echo FAILED
else
	if ! cmp $DATA/get.http $TOUT/data.0000.c2s
	then
		echo "Client requests do not match"
		echo FAILED
		RET=1
	elif ! cmp $DATA/onics.html $TOUT/data.0001.s2c
	then
		echo "Server responses do not match"
		echo FAILED
		RET=1
	else
		echo PASSED
	fi
fi
echo "---------------"
echo
exit $RET
