#include <tap.h>
#define MP_TEST_PROGRAM 1
#include "../check_snmp_cpu.c"
int main(int argc, char **argv)
{
	plan_tests(1);
	ok(12 == 12, "Yay! We did it!");
	return exit_status();
}
