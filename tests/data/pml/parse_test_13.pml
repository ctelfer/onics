# Test for incorrect and correct variable usage in patterns and rules
#
int global = 0;
?- global == 1 -? { print "good"; }
?- 1 == 1 -? { x = 5; print "good"; }
?- y == 1 -? { print "bad"; }
