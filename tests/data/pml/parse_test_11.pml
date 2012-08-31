# Scalar variable index test
#
# This should fail:  can't index a scalar global.
#
int x = 0;

?- x[1,1] == 0 -? { print "equal"; }
