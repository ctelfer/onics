#!/bin/sh

[ $# -lt 1 ] && echo "need a filename" >&2 && exit 1

set -e


cg() {
	echo Building from $1
	base=`echo $1 | sed -e 's/\.pml$//'`
	../../bin/pml -i $1 -c $base.nprg
	../../bin/nvmas -d $base.nprg > $base.nvas
	rm $base.nprg 
}


if [ $1 = "all" ]
then
	for f in cg*.pml
	do 
		cg $f
	done
else
	cg $1
fi
