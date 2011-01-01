#!/bin/sh

if [ $# -lt 2 ] ; then
	echo "usage: $0 testscript outfile"
	exit 1
fi

while read l
do    
	echo $l 
	echo "--------------------" 
	eval $l 2>&1 
	echo "--------------------"
	echo
done < $1 > $2
