int fn1(int a1, char a2) {
     int a0 = a2 * 0x16;
	return a1*2 + a0;
}

int fn2(int a1) {
     int a0 = a1 * 0x16;
	return (a1^0xff01) + a0;
}

int main(void) {
     fn1(2,'a');
     fn2(3);
     return 1;
}
