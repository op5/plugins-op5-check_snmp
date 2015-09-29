/**
 * Check system load average over snmp
 */
const char *progname = "check_snmp_load_avg";
const char *program_name = "check_snmp_load_avg"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <stdio.h>

#define DEFAULT_TIME_OUT 15                  /* only used for help text */

#define LOAD_TABLE "1.3.6.1.4.1.2021.10.1.5" /* laLoadInt */
#define LOAD_SUBIDX_LaLoad1 1
#define LOAD_SUBIDX_LaLoad5 2
#define LOAD_SUBIDX_LaLoad15 3

enum o_monitortype_t {
	MONITOR_TYPE__LOAD1,
	MONITOR_TYPE__LOAD5,
	MONITOR_TYPE__LOAD15,
	MONITOR_TYPE__LOAD
};

static int process_arguments (int, char **);
void print_help (void);
void print_usage (void);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__LOAD1;

struct cpu_info {
	float Load1;
	float Load5;
	float Load15;
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

static struct cpu_info *check_cpu_ret(mp_snmp_context *ss, int statemask)
{
	struct cpu_info *ci = (struct cpu_info *) malloc(sizeof(struct cpu_info));
	memset(ci, 0, sizeof(struct cpu_info));
	if (0 != mp_snmp_walk(ss, LOAD_TABLE, NULL, cpu_callback, ci, NULL)) {
		free(ci);
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	mp_debug(3,"load1: %f, load5: %f, load15 %f\n",
				ci->Load1, ci->Load5, ci->Load15);

	return ci;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community>\n",progname);
	printf ("[-w<warn_range>] [-c<crit_range>] [-t <timeout>] [-T <type>]\n");
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
	printf ("	%s\n", _("load"));
	printf ("	%s\n", _("load1"));
	printf ("	%s\n", _("load5"));
	printf ("	%s\n", _("load15"));
	mp_snmp_argument_help();
	printf (UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
static int process_arguments (int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;

	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	struct option longopts[] = {
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
				if (0==strcmp(optarg, "load")) {
					o_monitortype = MONITOR_TYPE__LOAD;
				} else if (0==strcmp(optarg, "load1")) {
					o_monitortype = MONITOR_TYPE__LOAD1;
				} else if (0==strcmp(optarg, "load5")) {
					o_monitortype = MONITOR_TYPE__LOAD5;
				} else if (0==strcmp(optarg, "load15")) {
					o_monitortype = MONITOR_TYPE__LOAD15;
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

int parse_thresholds(char **legacy_thrs, char *threshold, size_t n_thresholds)
{
	char *legacy_token = "";
	size_t i = 0;
	legacy_token = strtok(threshold, ",");

	while (legacy_token) {
		legacy_thrs[i++] = legacy_token;
		legacy_token = strtok(NULL, ",");
	}
	if (i != n_thresholds) {
		die(STATE_UNKNOWN, _("Warning and critical thresholds only take three "
			"arguments (STRING,STRING,STRING)\n"));
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	thresholds *thresh;
	struct cpu_info *ptr;
	int i, result = STATE_UNKNOWN;
	int legacy_temp_result = STATE_UNKNOWN;
	char *legacy_warn1 = "", *legacy_warn5 = "", *legacy_warn15 = "";
	char *legacy_crit1 = "", *legacy_crit5 = "", *legacy_crit15 = "";

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
	 * and check if we need to run the plugin in
	 * legacy mode for CPU load
	 */
	if (o_monitortype != MONITOR_TYPE__LOAD)
		set_thresholds(&thresh, warn_str, crit_str);

	if (o_monitortype == MONITOR_TYPE__LOAD)
	{
		/* Parse thresholds, return FALSE on error, TRUE on success */
		char *legacy_warn_thrs[] = {legacy_warn1, legacy_warn5, legacy_warn15};
		size_t n_thresholds = sizeof(legacy_warn_thrs) / sizeof(legacy_warn_thrs[0]);

		i = parse_thresholds(legacy_warn_thrs, warn_str, n_thresholds);
		if (FALSE == i)
			die(STATE_UNKNOWN, _("Could not parse warning thresholds\n"));

		char *legacy_crit_thrs[] = {legacy_crit1, legacy_crit5, legacy_crit15};
		n_thresholds = sizeof(legacy_crit_thrs) / sizeof(legacy_crit_thrs[0]);

		i = parse_thresholds(legacy_crit_thrs, crit_str, n_thresholds);
		if (FALSE == i)
			die(STATE_UNKNOWN, _("Could not parse critical thresholds\n"));

		set_thresholds(&thresh, legacy_warn_thrs[0], legacy_crit_thrs[0]);
		legacy_temp_result = get_status((float)ptr->Load1, thresh);
		result = max_state(legacy_temp_result, result);

		set_thresholds(&thresh, legacy_warn_thrs[1], legacy_crit_thrs[1]);
		legacy_temp_result = get_status((float)ptr->Load5, thresh);
		result = max_state(legacy_temp_result, result);

		set_thresholds(&thresh, legacy_warn_thrs[2], legacy_crit_thrs[2]);
		legacy_temp_result = get_status((float)ptr->Load15, thresh);
		result = max_state(legacy_temp_result, result);

		printf("%s: 1, 5, 15 min load average: %.2f, %.2f, %.2f ",
			state_text(result), (float)ptr->Load1,(float)ptr->Load5,
			(float)ptr->Load15);
		printf("|'Load1'=%.2f;%s;%s 'Load5'=%.2f;%s;%s "
			"'Load15'=%.2f;%s;%s",
			ptr->Load1, legacy_warn_thrs[0], legacy_crit_thrs[0],
			ptr->Load5, legacy_warn_thrs[1], legacy_crit_thrs[1],
			ptr->Load15, legacy_warn_thrs[2], legacy_crit_thrs[2]);
	}

	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__LOAD1:
			result = get_status((float)ptr->Load1, thresh);
			printf("%s: 1 min load average: %.2f ",
				state_text(result), ptr->Load1);
			printf("|'Load1'=%.2f;%s;%s", ptr->Load1, warn_str, crit_str);
			break;
		case MONITOR_TYPE__LOAD5:
			result = get_status((float)ptr->Load5, thresh);
			printf("%s: 5 min load average: %.2f ",
				state_text(result), (float)ptr->Load5);
			printf("|'Load5'=%.2f;%s;%s", ptr->Load5, warn_str, crit_str);
			break;
		case MONITOR_TYPE__LOAD15:
			result = get_status((float)ptr->Load15, thresh);
			printf("%s: 15 min load average: %.2f ",
				state_text(result), (float)ptr->Load15);
			printf("|'Load15'=%.2f;%s;%s",
				ptr->Load15, warn_str, crit_str);
			break;
		case MONITOR_TYPE__LOAD:
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
