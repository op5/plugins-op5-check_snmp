/**
 * Check system memory over snmp
 * Add a big description
 */
const char *progname = "check_snmp_cpu";
const char *program_name = "check_snmp_cpu"; /* for coreutils libs */
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include "utils_snmp.h"
#include <stdio.h>					/* to calculate iowait */
#include <time.h>					/* to calculate iowait */
#include "errno.h"

#define DEFAULT_COMMUNITY "public" 	/* only used for help text */
#define DEFAULT_PORT "161"			/* only used for help text */
#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define LOAD_TABLE "1.3.6.1.4.1.2021.10.1.5" /* laLoadInt */
#define LOAD_SUBIDX_LaLoad1 1
#define LOAD_SUBIDX_LaLoad5 2
#define LOAD_SUBIDX_LaLoad15 3

#define SYSTEMSTATS_TABLE ".1.3.6.1.4.1.2021.11" /* Scalars */
#define SYSTEMSTATS_SUBIDX_CpuRawWait 54 	/* of type counter */

#define HRDEVICE_TABLE ".1.3.6.1.2.1.25.3.3.1" /* hrDeviceTable */
#define HRDEVICE_SUBIDX_TYPE 1

enum o_monitortype_t {
	MONITOR_TYPE__LOAD1,
	MONITOR_TYPE__LOAD5,
	MONITOR_TYPE__LOAD15,
	MONITOR_TYPE__LOAD,
	MONITOR_TYPE__IOWAIT
};

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__LOAD1;
int o_perfdata = 1; /* perfdata on per default */

struct cpu_info {
	time_t timeval;
	float Load1;
	float Load5;
	float Load15;
	int CpuRawWait;
	int NumberOfCpus;
};

static int cpu_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;

	switch (v->name[10]) {
		case LOAD_SUBIDX_LaLoad1:
			cc->Load1=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load1\n",cc->Load1);
			break;
		case LOAD_SUBIDX_LaLoad5:
			cc->Load5=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load5\n",cc->Load5);
			break;
		case LOAD_SUBIDX_LaLoad15:
			cc->Load15=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load15\n",cc->Load15);
			break;
	}
	return EXIT_SUCCESS;
}

static int io_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	switch (v->name[8]) {
		case SYSTEMSTATS_SUBIDX_CpuRawWait:
			cc->CpuRawWait=*v->val.integer;
			mp_debug(3,"%d Number of 'ticks' spent waiting for I/O\n",cc->CpuRawWait);
			break;
	}
	return EXIT_SUCCESS;
}

static int type_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
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
	struct cpu_info *ci = (struct cpu_info *) malloc(sizeof(struct cpu_info));
	memset(ci, 0, sizeof(struct cpu_info));
	if (0 != mp_snmp_walk(ss, LOAD_TABLE, NULL, cpu_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}
	if (0 != mp_snmp_walk(ss, SYSTEMSTATS_TABLE, NULL, io_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}
	if (0 != mp_snmp_walk(ss, HRDEVICE_TABLE, NULL, type_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	mp_debug(3,"Load-1: %f, Load-5: %f, Load-15 %f, CpuRawWait %d\n",
				ci->Load1, ci->Load5, ci->Load15, ci->CpuRawWait);

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
	printf ("%s\n", _("Check status of remote machines and obtain system information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf (" %s\n", "-T, --type=STRING");
	printf ("	%s\n", _("cpu_load_1"));
	printf ("	%s\n", _("cpu_load_5"));
	printf ("	%s\n", _("cpu_load_15"));
	printf ("	%s\n", _("cpu_load"));
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
		{"usage", no_argument, 0, 'u'},
		{"perfdata", no_argument, 0, 'f'},
		{"type", required_argument, 0, 'T'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};
	
	if (argc < 2)
		usage4 (_("Could not parse arguments"));

	optary = calloc(3, ARRAY_SIZE(longopts));
	i = 0;
	optary[i++] = '+';
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
			case 'u':
				print_usage();
				exit(STATE_OK);
				break;
			case 'f':
				o_perfdata = 0;
				break;
			case 'T':
				if (0==strcmp(optarg, "cpu_load_1")) {
					o_monitortype = MONITOR_TYPE__LOAD1;
				} else if (0==strcmp(optarg, "cpu_load_5")) {
					o_monitortype = MONITOR_TYPE__LOAD5;
				} else if (0==strcmp(optarg, "cpu_load_15")) {
					o_monitortype = MONITOR_TYPE__LOAD15;
				} else if (0==strcmp(optarg, "cpu_load")) {
					o_monitortype = MONITOR_TYPE__LOAD;
				} else if (0==strcmp(optarg, "cpu_io_wait")) {
					o_monitortype = MONITOR_TYPE__IOWAIT;
				} else {
					die(STATE_UNKNOWN, _("Wrong parameter for -T.\n"));
				}
				break;
		}
	}
	free(optary);
	return TRUE;
}

int main(int argc, char **argv)
{
	static thresholds *thresh;
	struct cpu_info *ptr;
	int result = STATE_UNKNOWN;
	int legacy_i, legacy_temp_result = STATE_UNKNOWN;
	char *legacy_warn1 = "", *legacy_warn5 = "", *legacy_warn15 = "";
	char *legacy_crit1 = "", *legacy_crit5 = "", *legacy_crit15 = "";
	char *legacy_token = "";
	
	mp_snmp_init(program_name, 0);
	np_init((char *)progname, argc, argv);
	
	/* Parse extra opts if any */
	argv=np_extra_opts(&argc, argv, progname);
	if ( process_arguments(argc, argv) == ERROR )
		usage4 (_("Could not parse arguments"));
	
	mp_snmp_finalize_auth(ctx);
	ptr = check_cpu_ret(ctx, ~0); /* get net-snmp cpu data */
	mp_snmp_deinit(program_name); /* deinit */

	/**
	 * set standard monitoring-plugins thresholds
	 * and check if we need to run the plugin in
	 * legacy mode for CPU load
	 */
	if (o_monitortype != MONITOR_TYPE__LOAD)
		set_thresholds(&thresh, warn_str, crit_str);
	
	if (o_monitortype == MONITOR_TYPE__LOAD)
	{
		legacy_token = strtok(warn_str, ",");
		for (legacy_i = 0; legacy_i < 3; legacy_i++)
		{
			if (legacy_i == 0 && legacy_token != NULL)
				legacy_warn1 = legacy_token;
			else if (legacy_i == 1 && legacy_token != NULL)
				legacy_warn5 = legacy_token;
			else if (legacy_i == 2 && legacy_token != NULL)
				legacy_warn15 = legacy_token;
			else
				die(STATE_UNKNOWN, _("Needs 3 warning arguments, -w STRING,STRING,STRING\n"));
			legacy_token = strtok(NULL, ",");
		}
		legacy_token = strtok(crit_str, ",");
		for (legacy_i = 0; legacy_i < 3; legacy_i++)
		{
			if (legacy_i == 0 && legacy_token != NULL)
				legacy_crit1 = legacy_token;
			else if (legacy_i == 1 && legacy_token != NULL)
				legacy_crit5 = legacy_token;
			else if (legacy_i == 2 && legacy_token != NULL)
				legacy_crit15 = legacy_token;
			else
				die(STATE_UNKNOWN, _("Needs 3 critical arguments, -c STRING,STRING,STRING\n"));
			legacy_token = strtok(NULL, ",");
		}
		
		set_thresholds(&thresh, legacy_warn1, legacy_crit1);
		legacy_temp_result = get_status((float)ptr->Load1, thresh);
		result = max_state(legacy_temp_result, result);
		
		set_thresholds(&thresh, legacy_warn5, legacy_crit5);
		legacy_temp_result = get_status((float)ptr->Load5, thresh);
		result = max_state(legacy_temp_result, result);
		
		set_thresholds(&thresh, legacy_warn15, legacy_crit15);
		legacy_temp_result = get_status((float)ptr->Load15, thresh);
		result = max_state(legacy_temp_result, result);
		
		printf("%s: %.2f, %.2f, %.2f CPU load average ", state_text(result), (float)ptr->Load1,(float)ptr->Load5,(float)ptr->Load15);
			if (o_perfdata == 1) {
				printf("|'CPU load-1'=%.2f;%s;%s 'CPU load-5'=%.2f;%s;%s 'CPU load-15'=%.2f;%s;%s",
					ptr->Load1, legacy_warn1, legacy_crit1,
					ptr->Load5, legacy_warn5, legacy_crit5,
					ptr->Load15, legacy_warn15, legacy_crit15);
			}
	}


	/**
	 * To check iowait we need to store the time and counter value
	 * and compare it to the previous value stored in a file.
	 */
	float iowait = 0;
	if (o_monitortype == MONITOR_TYPE__IOWAIT) {
		time_t fftime = 0, timenow = time(0);
		int ffcpurawwait = 0;
		np_enable_state(NULL, 1);
		state_data *previous_state = np_state_read();
		
		if (previous_state != NULL) {
			if (sscanf(previous_state->data, "%d %ld", &ffcpurawwait, &fftime) == 2) {
				if ((timenow-fftime) == 0)
					die(STATE_UNKNOWN, _("The time interval needs to be at least one second.\n"));
				else if (ffcpurawwait > ptr->CpuRawWait)
					die(STATE_UNKNOWN, _("The iowait counter rolled over.\n"));
				iowait = (ptr->CpuRawWait-ffcpurawwait)/((timenow-fftime)*ptr->NumberOfCpus);
				mp_debug(3,"iowait: %.2f\n", iowait);
			}
		}
		char *state_string;
		asprintf(&state_string, "%d %ld", ptr->CpuRawWait, timenow);
		np_state_write_string(0, state_string);
		free(state_string);
	}

	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__LOAD1:
			result = get_status((float)ptr->Load1, thresh);
			printf("%s: %.2f CPU load-1 ", state_text(result), ptr->Load1);
			if (o_perfdata == 1) {
				printf("|'CPU load-1'=%.2f;%s;%s", ptr->Load1, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__LOAD5:
			result = get_status((float)ptr->Load5, thresh);
			printf("%s: %.2f CPU load-5 ", state_text(result), (float)ptr->Load5);
			if (o_perfdata == 1) {
				printf("|'CPU load-5'=%.2f;%s;%s",
					ptr->Load5, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__LOAD15:
			result = get_status((float)ptr->Load15, thresh);
			printf("%s: %.2f CPU load-15 ", state_text(result), (float)ptr->Load15);
			if (o_perfdata == 1) {
				printf("|'CPU load-15'=%.2f;%s;%s",
					ptr->Load15, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__LOAD:
			break;
		case MONITOR_TYPE__IOWAIT:
			result = get_status(iowait, thresh);
			printf("%s: %.2f CPU I/O wait ", state_text(result), iowait);
			if (o_perfdata == 1) {
				printf("|'CPU I/O wait'=%.2f;%s;%s",
					iowait, warn_str, crit_str);
			}
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
