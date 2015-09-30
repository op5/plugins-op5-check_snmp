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

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";

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
	struct cpu_info *ci = malloc(sizeof(struct cpu_info));
	ci->Load1=-1;
	ci->Load5=-1;
	ci->Load15=-1;
	if (0 != mp_snmp_walk(ss, LOAD_TABLE, NULL, cpu_callback, ci, NULL)) {
		free(ci);
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	if (ci->Load1 == -1 || ci->Load5 == -1 || ci->Load15 == -1) {
		die(STATE_UNKNOWN, "UNKNOWN: Could not fetch the values at %s. "
			"Please check your config file for SNMP and make sure you have access\n", LOAD_TABLE);
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
				if (0!=strcmp(optarg, "load")) {
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

/**
 * Takes an array of thresholds and a comma separeted threshold string which
 * gets parsed into individual ranges in the array. The function also needs to
 * know the maximum number of thresholds it should parse.
 */
static int parse_thresholds(char **thrs, char *threshold, size_t n_thresholds)
{
	size_t i = 0;
	char *token;
	token = strtok(threshold, ",");

	while (token) {
		if (i >= n_thresholds) {
			die(STATE_UNKNOWN, _("Too many arguments for warning and critical thresholds\n"));
			return FALSE;
		}
		thrs[i] = token;
		token = strtok(NULL, ",");
		i++;
	}

	return TRUE;
}

int main(int argc, char **argv)
{
	thresholds *thresh;
	struct cpu_info *ptr;
	int result = STATE_UNKNOWN;
	int temp_result = STATE_UNKNOWN;
	char *warn_thrs[] = {"", "", ""};
	char *crit_thrs[] = {"", "", ""};
	size_t n_thresholds;

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
	 * Parse thresholds and set the result to the worst state
	 */
	n_thresholds= ARRAY_SIZE(warn_thrs);
	parse_thresholds(warn_thrs, warn_str, n_thresholds);

	n_thresholds = ARRAY_SIZE(crit_thrs);
	parse_thresholds(crit_thrs, crit_str, n_thresholds);

	set_thresholds(&thresh, warn_thrs[0], crit_thrs[0]);
	temp_result = get_status((float)ptr->Load1, thresh);
	result = max_state(temp_result, result);

	set_thresholds(&thresh, warn_thrs[1], crit_thrs[1]);
	temp_result = get_status((float)ptr->Load5, thresh);
	result = max_state(temp_result, result);

	set_thresholds(&thresh, warn_thrs[2], crit_thrs[2]);
	temp_result = get_status((float)ptr->Load15, thresh);
	result = max_state(temp_result, result);

	printf("%s: 1, 5, 15 min load average: %.2f, %.2f, %.2f ",
		state_text(result), (float)ptr->Load1,(float)ptr->Load5,
		(float)ptr->Load15);
	printf("|'Load1'=%.2f;%s;%s 'Load5'=%.2f;%s;%s "
		"'Load15'=%.2f;%s;%s",
		ptr->Load1, warn_thrs[0], crit_thrs[0],
		ptr->Load5, warn_thrs[1], crit_thrs[1],
		ptr->Load15, warn_thrs[2], crit_thrs[2]);

	printf("\n");
	free(ctx);
	free(ptr);

	return result;
}
