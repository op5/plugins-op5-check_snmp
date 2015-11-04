#include <tap.h>
#define MP_TEST_PROGRAM 1
#include "../check_by_snmp_cpu.c"
int main(int argc, char **argv)
{
	struct cpu_info old, fetched;
	struct pct_cpu_info pct;
	mp_verbosity = 0;

	memset(&old, 0, sizeof(old));
	memset(&fetched, 0, sizeof(fetched));

	plan_tests(5);

	old.counter[COUNTER_idle] = 0;
	fetched.counter[COUNTER_idle] = 95;
	calculate_cpu_usage(&pct, &fetched, &old);
	ok(pct.counter[COUNTER_idle] == 100.0, "Idle cpu is idle");

	fetched.counter[COUNTER_idle] = 95;
	fetched.counter[COUNTER_iowait] = 5;
	calculate_cpu_usage(&pct, &fetched, &old);
	ok(pct.counter[COUNTER_idle] == 95.0, "95%% idle is 95%% idle");
	ok(pct.counter[COUNTER_iowait] == 5.0, "5%% iowait is 5%% iowait");

	old.counter[COUNTER_idle] = (1UL << 32) - 5;
	ok(old.counter[COUNTER_idle] > 10, "Verify that test doesn't overflow to a negative value");
	fetched.counter[COUNTER_idle] = 0;
	calculate_cpu_usage(&pct, &fetched, &old);
	ok(pct.counter[COUNTER_iowait] == 50, "half idle is half idle, with overflow");

	return exit_status();
}
