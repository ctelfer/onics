#!/bin/sh

ERR=0
CHANGED=0

OBIN=../bin
TOUT=tmp


codegen() {
	FAIL=0

	echo Compiling and then disassembling $1
	base=`echo $1 | sed -e 's|^.*/||' -e 's/\.pml$//'`
	$OBIN/pml -f $1 -c $TOUT/$base.nprg
	if [ $? -ne 0 ] ; then
		echo Error compiling $TOUT/$base.nprg
		FAIL=1
	fi

	$OBIN/nvmas -d $TOUT/$base.nprg > $TOUT/$base.nvas
	if [ $? -ne 0 ] ; then
		echo Error disassembling $TOUT/$base.nvas
		FAIL=1
	fi

	rm $TOUT/$base.nprg 

	if [ $FAIL -eq 0 ] ; then
		if grep -i DEADC0DE $TOUT/$base.nvas > /dev/null 2>&1
		then
			echo "Found DEADCODE in $base.nvas."
			echo "This should have been removed!"
			ERR=1
		elif ! [ -f data/pml/$base.nvas ]
		then
			echo $1 does not have a disassembly for comparison

		elif ! cmp data/pml/$base.nvas $TOUT/$base.nvas
		then

			echo Instruction selection for $base.pml changed
			CHANGED=1

		fi
	else
		ERR=1
	fi
}


for f in `echo data/pml/pml_test*.pml | sort`
do 
	codegen $f
done

if [ $CHANGED -eq 0 -a $ERR -eq 0 ] ; then
	echo
	echo "No changes in code generation detected"
fi

exit $ERR
