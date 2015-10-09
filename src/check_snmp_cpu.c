/**
 * Check cpu over snmp
 */
const char *progname = "check_snmp_cpu";
const char *program_name = "check_snmp_cpu"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include "utils_snmp.h"
#include <stdio.h> /* to calculate iowait */
#include <time.h>  /* to calculate iowait */

#define DEFAULT_TIME_OUT 15 /* only used for help text */

#define SYSTEMSTATS_TABLE ".1.3.6.1.4.1.2021.11" /* Scalars */
#define SYSTEMSTATS_SUBIDX_CpuRawWait 54         /* of type counter */

#define HRDEVICE_TABLE ".1.3.6.1.2.1.25.3.3.1"   /* hrDeviceTable */
#define HRDEVICE_SUBIDX_TYPE 1

enum o_monitortype_t {
	MONITOR_TYPE__IOWAIT
};

int asprintf(char **strp, const char *fmt, ...);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__IOWAIT;
int cpu_found = FALSE;

struct cpu_info {
	time_t time_now;
	int CpuRawWait;
	int NumberOfCpus;
};

static int io_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	switch (v->name[8]) {
		case SYSTEMSTATS_SUBIDX_CpuRawWait:
			cc->CpuRawWait=*v->val.integer;
			mp_debug(3,"%d Number of 'ticks' spent waiting for I/O\n",
				cc->CpuRawWait);
			break;
	}
	return EXIT_SUCCESS;
}

static int type_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	cpu_found = TRUE;

	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	switch (v->name[10]) {
		case HRDEVICE_SUBIDX_TYPE:
			cc->NumberOfCpus++;
			mp_debug(3,"%d CPU found\n",cc->NumberOfCpus);
			if (cc->NumberOfCpus == 0) {
				die(STATE_UNKNOWN, _("The number of CPUs is 0\n"));
			}
			break;
	}
	return EXIT_SUCCESS;
}

struct cpu_info *check_cpu_ret(mp_snmp_context *ss, int statemask)
{
	struct cpu_info *ci = malloc(sizeof(struct cpu_info));
	ci->CpuRawWait=-1;

	if (0 != mp_snmp_walk(ss, SYSTEMSTATS_TABLE, NULL, io_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}
	if (0 != mp_snmp_walk(ss, HRDEVICE_TABLE, NULL, type_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	if (ci->CpuRawWait == -1 || !cpu_found) {
		die(STATE_UNKNOWN, "UNKNOWN: Could not fetch the values at %s and %s. "
		"Please check your config file for SNMP and make sure you have access\n"
		, SYSTEMSTATS_TABLE, HRDEVICE_TABLE);
	}

	mp_debug(3,"CpuRawWait %d\n",
				ci->CpuRawWait);

	return ci;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community>\n",progname);
	printf ("[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]\n");
	printf ("([-P snmp version] [-N context] [-L seclevel] [-U secname]\n");
	printf ("[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])\n");
}

void print_help (void)
{
	print_revision (progname, NP_VERSION);
	printf ("%s\n", _("Check status of remote machines and obtain "
		"system information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf (" %s\n", "-T, --type=STRING");
	printf ("	%s\n", _("cpu_io_wait"));
	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
int process_arguments (int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;

	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"type", required_argument, 0, 'T'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	if (argc < 2)
		usage4 (_("Could not parse arguments"));

	optary = calloc(3, ARRAY_SIZE(longopts));
	i = 0;
	optary[i++] = '?';
	for (x = 0; longopts[x].name; x++) {
		struct option *o = &longopts[x];
		if (o->val >= CHAR_MAX || o->val <= 0)
			continue;
		if (o->val < CHAR_MAX)
			optary[i++] = o->val;
		if (o->has_arg)
			optary[i++] = ':';
		if (o->has_arg == optional_argument)
			optary[i++] = ':';
	}

	mp_debug(3,"optary: %s\n", optary);

	while (1) {
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;
		if (!mp_snmp_handle_argument(ctx, c, optarg))
			continue;

		switch (c) {
			case 'w':
				warn_str = optarg;
				break;
			case 'c':
				crit_str = optarg;
				break;
			case 'h':
				print_help();
				exit(STATE_OK);
				break;
			case 'V':
				print_revision (progname, NP_VERSION);
				exit (STATE_OK);
			case 'v':
				mp_verbosity++;
				break;
			case 'T':
				if (0==strcmp(optarg, "cpu_io_wait")) {
					o_monitortype = MONITOR_TYPE__IOWAIT;
				} else {
					die(STATE_UNKNOWN, _("Wrong parameter for -T.\n"));
				}
				break;
			default:
				exit(STATE_UNKNOWN);
				break;
		}
	}
	free(optary);

	if (optind != argc) {
		printf("%s: %s: ", state_text(STATE_UNKNOWN),
			_("Unhandled arguments present"));
		for (i = optind - 1; i < argc; i++) {
			printf("%s%s", argv[i], i == argc - 1 ? "\n" : ", ");
		}
		exit(STATE_UNKNOWN);
	}

	return TRUE;
}

#ifndef MP_TEST_PROGRAM
int main(int argc, char **argv)
{
	static thresholds *thresh;
	struct cpu_info *ptr;
	int result = STATE_UNKNOWN;

	mp_snmp_init(program_name, 0);
	np_init((char *)progname, argc, argv);

	/* Parse extra opts if any */
	argv=np_extra_opts(&argc, argv, progname);
	if ( process_arguments(argc, argv) == ERROR )
		usage4 (_("Could not parse arguments"));

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	};

	ptr = check_cpu_ret(ctx, ~0); /* get net-snmp cpu data */
	mp_snmp_deinit(program_name); /* deinit */

	/**
	 * set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	/**
	 * To check iowait we need to store the time and counter value
	 * and compare it to the previous value stored in a file.
	 */
	float iowait = 0;
	if (o_monitortype == MONITOR_TYPE__IOWAIT) {
		time_t fftime = 0;
		ptr->time_now = time(0);
		int ffcpurawwait = 0;
		char *state_string = NULL;

		np_enable_state(NULL, 1);
		state_data *previous_state = np_state_read();

		if (previous_state != NULL) {
			if (sscanf(previous_state->data, "%d %ld", &ffcpurawwait,
				&fftime) == 2)
			{
				if ((ptr->time_now - fftime) == 0)
					die(STATE_UNKNOWN, _("The time interval needs to be "
						"at least one second.\n"));
				else if (ffcpurawwait > ptr->CpuRawWait)
					die(STATE_UNKNOWN, _("The iowait counter rolled over.\n"));
				iowait = (ptr->CpuRawWait - ffcpurawwait) /
					((ptr->time_now - fftime) * ptr->NumberOfCpus);
				mp_debug(3,"iowait: %.2f\n", iowait);
			}
		}
		if (asprintf(&state_string, "%d %ld", ptr->CpuRawWait,
			ptr->time_now) >= 3)
		{
			np_state_write_string(0, state_string);
		}
		free(state_string);
	}

	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__IOWAIT:
			result = get_status(iowait, thresh);
			printf("%s: %.2f CPU I/O wait ", state_text(result), iowait);
			printf("|'CPU I/O wait'=%.2f;%s;%s",
				iowait, warn_str, crit_str);

			break;
		default:
			usage4 (_("Could not parse arguments for -T"));
			break;
	}
	printf("\n");

	free(ctx);
	free(ptr);

	return result;
}
#endif /* MP_TEST_PROGRAM */
