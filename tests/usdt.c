#include <windows.h>
#include <stdio.h>
#include <sys/sdt.h>
#include <stdio.h>

int Point = 99;

static void
foo(void)
{
	DTRACE_PROBE(test_prov_one, probe1);
	printf("static function foo()\n");
	DTRACE_PROBE(test_prov_one, probe1);
}

int main(int argc, char **argv)
{
	foo();
	
	DTRACE_PROBE(test_prov_one, probe1);
	printf("Hello World\n");
	DTRACE_PROBE(test_prov_one, probe2);
	return 0;
		
}