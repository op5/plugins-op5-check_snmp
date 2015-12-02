#include <tap.h>
#include "../utils_snmp.h"

#define ASCIINAME "THENAME"
#define THENAME_OID ".1.3.6.1.4.1.8072.1.3.2.3.1.1.7.84.72.69.78.65.77.69"
#define NONAME_OID  ".1.3.6.1.4.1.8072.1.3.2.3.1.1"

char *progname = "utils_snmp tester";
void print_usage(void) {}

int main(int argc, char **argv)
{
	struct mp_snmp_oid o;
	oid orig_oid[MAX_OID_LEN];
	size_t orig_oid_len = MAX_OID_LEN;
	char *name;

	plan_tests(2);

	mp_snmp_init("utils_snmp tests", 0);

	snmp_parse_oid(THENAME_OID, orig_oid, &orig_oid_len);
	name = mp_snmp_asciioid_extract(&orig_oid[13]);
	ok(0 == strcmp(ASCIINAME, name), "Names must match");
	free(name);

	o.len = MAX_OID_LEN;
	snmp_parse_oid(NONAME_OID, o.id, &o.len);
	mp_snmp_asciioid_append(&o, ASCIINAME);
	ok(snmp_oid_compare(orig_oid, orig_oid_len, o.id, o.len) == 0, "OID's must be identical");

	return exit_status();
}
