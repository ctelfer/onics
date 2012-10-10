# Test 'exit()' intrinsic
#

# should only get the 'hello'
BEGIN {
    print "hello world\n";
    exit(1);
    print "goodbye world\n";
}
