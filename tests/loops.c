//ex. dtrace -n "pid$target:loops64::entry {@[ustack()]=count();}" -c loops64.exe
//cl.exe  /Zi /Feloops[64/32].exe loops.c
//gcc -o loops loops.c

#include <stdio.h>
#include <windows.h>


void call_1(void)
{

	Sleep(1220);

	printf("call_1\n");
}

void call_2(void)
{

	Sleep(1030);

	printf("call_2\n");
}
void call_3(void)
{
	Sleep(100);
	printf("call_3\n");

}
		
int main()
{

	while(1) {
		call_1();
		Sleep(1000);
		call_2();
		Sleep(1000);
		call_3();
		
	}
	return 0;
}