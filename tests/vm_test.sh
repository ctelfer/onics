#!/bin/sh

OBIN=../bin
TOUT=tmp
VMOUT=data/testvm
PDIR=data/packets
ERR=0

check_output() {
	FAIL=0
	for file in $VMOUT/vm_test_$1.*
	do
		BASE=`echo $file | sed -e 's|^.*/||g'`
		if ! cmp $file $TOUT/$BASE
		then
			echo $file and $TOUT/$BASE differ
			echo FAILED
			FAIL=1
			ERR=1
		fi
	done
	if [ $FAIL -eq 0 ]
	then
		echo PASSED
	fi
}

echo ---------------------
echo VM Test 0: Find TCP
bin/testvm -p 0 < $PDIR/sample.xpkt > $TOUT/vm_test_0.out 2> $TOUT/vm_test_0.err
check_output 0
echo ---------------------
echo


echo ---------------------
echo VM Test 1: Find TCP error packets
bin/testvm -p 1 < $PDIR/modified.xpkt > $TOUT/vm_test_1.out 2> $TOUT/vm_test_1.err
check_output 1
echo ---------------------
echo


echo ---------------------
echo VM Test 2: Test for UDP packets
bin/testvm -p 2 < $PDIR/sample.xpkt > $TOUT/vm_test_2.out 2> $TOUT/vm_test_2.err
check_output 2
echo ---------------------
echo


echo ---------------------
echo VM Test 3: Fix all checksums
bin/testvm -p 3 < $PDIR/modified.xpkt 2> $TOUT/vm_test_3.err1 |
	$OBIN/x2hpkt > $TOUT/vm_test_3.out 2> $TOUT/vm_test_3.err2
check_output 3
echo ---------------------
echo


echo ---------------------
echo VM Test 4: Toggle DF flag and fix all checksums
bin/testvm -p 4 < $PDIR/sample.xpkt 2> $TOUT/vm_test_4.err1 |
	$OBIN/x2hpkt > $TOUT/vm_test_4.out 2> $TOUT/vm_test_4.err2
check_output 4
echo ---------------------
echo


echo ---------------------
echo VM Test 5: Print 10 \'.\'s via loop
bin/testvm -p 5 > $TOUT/vm_test_5.out 2> $TOUT/vm_test_5.err
check_output 5
echo ---------------------
echo


echo ---------------------
echo VM Test 6: Print \'hello world\'
bin/testvm -p 6 > $TOUT/vm_test_6.out 2> $TOUT/vm_test_6.err
check_output 6
echo ---------------------
echo


echo ---------------------
echo VM Test 7: Test recursive functions with the fibonacci sequence
bin/testvm -p 7 > $TOUT/vm_test_7.out 2> $TOUT/vm_test_7.err
check_output 7
echo ---------------------
echo


echo ---------------------
echo VM Test 8: Duplicate the first packet and drop the rest
bin/testvm -p 8 < $PDIR/sample.xpkt 2> $TOUT/vm_test_8.err1 |
	$OBIN/x2hpkt > $TOUT/vm_test_8.out 2> $TOUT/vm_test_8.err2
check_output 8
echo ---------------------
echo


echo ---------------------
echo VM Test 9: Extract first 16 bytes from first data TCP and clobber 12
bin/testvm -p 9 < $PDIR/sample.xpkt 2> $TOUT/vm_test_9.err1 |
	$OBIN/x2hpkt > $TOUT/vm_test_9.out 2> $TOUT/vm_test_9.err2
check_output 9
echo ---------------------
echo


echo ---------------------
echo VM Test 10: Hex dump the packets
bin/testvm -p 10 < $PDIR/sample.xpkt > $TOUT/vm_test_10.out 2> $TOUT/vm_test_10.err
check_output 10
echo ---------------------
echo

echo ---------------------
echo VM Test 11: Mask equality tests for 0x45000034
bin/testvm -p 11 < $PDIR/sample.xpkt > $TOUT/vm_test_11.out 2> $TOUT/vm_test_11.err
check_output 11
echo ---------------------
echo

exit $ERR
