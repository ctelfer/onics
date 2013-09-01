# Test implicit length declaration of str variables.
#
str impl[]   = "Hello World";
str expl[16] = "aaaaAAAAaaaaAAA\n";
BEGIN {
	expl = impl;
	print expl;
}
