#!/bin/sh

TBIN=bin
TOUT=tmp

rm -fr $TOUT/*
ERR=0


parse_test()
{
	echo -----------------
	echo -n "Parse Test $1: "

	head -1 data/pml/parse_test_$1.pml | sed -e 's/# *//'

	${TBIN}/testpmlparse 9 < data/pml/parse_test_$1.pml \
		> tmp/parse_test_$1.out 2> $TOUT/parse_test_$1.err

	if [ ! -f data/pml/parse_test_$1.out -o \
	     ! -f data/pml/parse_test_$1.err ]
        then
		echo SKIPPED
		echo -----------------
		echo
		return
	fi

	if cmp data/pml/parse_test_$1.out $TOUT/parse_test_$1.out &&
	   cmp data/pml/parse_test_$1.err $TOUT/parse_test_$1.err
	then
		echo PASSED
	else
		echo FAILED
		ERR=1
	fi

	echo -----------------
	echo
}


for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
do
	parse_test $i
done

exit $ERR
