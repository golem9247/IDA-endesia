int fn1(int a1, char a2) {
	return a1*2 + a2;
}

int fn2(int a1) {
	return a1*3;
}

int main(void) {
     fn1(2,'a');
     fn2(3);
     return 1;
}
