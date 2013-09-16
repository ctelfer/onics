# Test implicit length declaration of str variables.
#
str impl[]   = "Hello World";
str expl[16] = "aaaaAAAAaaaaAAAA";
BEGIN {
	expl = impl;
	print expl;
}
