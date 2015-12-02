#include <tap.h>
#define MP_TEST_PROGRAM 1
#include "../check_by_snmp_procs.c"

struct fw_basename_test {
	char *in;
	char *exp;
} fw_basename_tests[] = {
	{"/sbin/dhclient", "dhclient"},
	{"/usr/bin/foo --lala", "foo"},
	{"foo", "foo"},
	{"foo --lala", "foo"},
};

int main(int argc, char **argv)
{
	unsigned int i;

	plan_tests(ARRAY_SIZE(fw_basename_tests));

	for (i = 0; i < ARRAY_SIZE(fw_basename_tests); i++) {
		struct fw_basename_test *t = &fw_basename_tests[i];
		char *ret = first_word_basename(t->in);
		ok(0 == strcmp(ret, t->exp), "'%s' expects '%s', got '%s'", t->in, t->exp, ret);
	}
	return exit_status();
}
