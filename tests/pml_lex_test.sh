#!/bin/sh

TBIN=bin
TOUT=tmp

rm -fr $TOUT/*
ERR=0


lex_test()
{
	echo -----------------
	echo -n "Lexical Analysis Test $1: "

	head -1 data/pml/parse_test_$1.pml | sed -e 's/# *//'

	${TBIN}/testpmllex < data/pml/parse_test_$1.pml \
		> tmp/lex_test_$1.out 2> $TOUT/lex_test_$1.err

	if [ $? -ne 0 ]
	then
		echo Error running test
		echo FAILED
		ERR=1
		return
	fi

	if [ ! -f data/pml/lex_test_$1.out -o ! -f data/pml/lex_test_$1.err ]
        then
		echo SKIPPED
		echo -----------------
		echo
		return
	fi

	if cmp data/pml/lex_test_$1.out $TOUT/lex_test_$1.out &&
	   cmp data/pml/lex_test_$1.err $TOUT/lex_test_$1.err
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
	lex_test $i
done

exit $ERR
