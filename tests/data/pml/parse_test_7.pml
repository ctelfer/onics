# Function parsing and return outside function
#
int test(int a, int b) {
	return a + b;
}

{
	a = test(a, b);
	return 5;
}
