# Test 'exit()' intrinsic
#

# should only get the 'hello'
BEGIN {
    print "hello world";
    exit(1);
    print "goodbye world";
}
