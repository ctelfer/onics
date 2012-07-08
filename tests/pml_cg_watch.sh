#!/bin/sh

ERR=0

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
		if ! cmp data/pml/$base.nvas $TOUT/$base.nvas
		then
			echo Instruction selection for $base.pml changed
		fi
	else
		ERR=1
	fi
}


for f in `echo data/pml/pml_test*.pml | sort`
do 
	codegen $f
done

exit $ERR
