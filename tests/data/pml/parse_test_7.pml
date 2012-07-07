# Function parsing and return outside function
#
int test(a, b) { 
	return a + b;
}

{
	a = test(a, b);
	return 5;
}
