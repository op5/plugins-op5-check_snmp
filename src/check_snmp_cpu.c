/**
 * Check cpu over snmp
 */
const char *progname = "check_snmp_cpu";
const char *program_name = "check_snmp_cpu"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include "utils_snmp.h"
#include <stdio.h>

#define DEFAULT_TIME_OUT 15 /* only used for help text */

/**
 * On a multi-processor system, the 'ssCpuRaw*' counters are cumulative over all
 * CPUs, so their sum will typically be N*100 (for N processors).
 */
#define SYSTEMSTATS_TABLE ".1.3.6.1.4.1.2021.11" /* UCD-SNMP-MIB */
#define SYSTEMSTATS_SUBIDX_ssCpuRawUser 50       /* Counter */
#define SYSTEMSTATS_SUBIDX_ssCpuRawNice 51       /* Counter */
#define SYSTEMSTATS_SUBIDX_ssCpuRawSystem 52     /* Counter can be wait+kernel*/
#define SYSTEMSTATS_SUBIDX_ssCpuRawIdle 53       /* Counter */
#define SYSTEMSTATS_SUBIDX_ssCpuRawWait 54       /* Counter */
#define SYSTEMSTATS_SUBIDX_ssCpuRawKernel 55     /* Counter */
#define SYSTEMSTATS_SUBIDX_ssCpuRawSteal 64      /* Counter */

enum {
	COUNTER_total = 0,
	COUNTER_user,
	COUNTER_system,
	COUNTER_iowait,
	COUNTER_kernel,
	COUNTER_steal,
	COUNTER_nice,
	COUNTER_idle
};
#define COUNTER_NELEMS (((int)COUNTER_idle)+1)

static const char *counter_names[] = {
	"total",
	"user",
	"system",
	"iowait",
	"kernel",
	"steal",
	"nice",
	"idle",
	NULL
};

static mp_snmp_context *ctx;
static char *warn_str = "100.0", *crit_str = "100.0"; /* never alert by default */
static int checktype = COUNTER_total; /* check total by default */
static int raw_found = FALSE;

struct cpu_info {
	int valid;
	unsigned int counter[COUNTER_NELEMS];
};

struct pct_cpu_info {
	float counter[COUNTER_NELEMS];
};

static int cpu_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	raw_found = TRUE;

	switch (v->name[8]) {
		case SYSTEMSTATS_SUBIDX_ssCpuRawUser:
			cc->counter[COUNTER_user]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawNice:
			cc->counter[COUNTER_nice]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawSystem:
			cc->counter[COUNTER_system]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawIdle:
			cc->counter[COUNTER_idle]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawWait:
			cc->counter[COUNTER_iowait]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawKernel:
			cc->counter[COUNTER_kernel]=*v->val.integer;
			break;
		case SYSTEMSTATS_SUBIDX_ssCpuRawSteal:
			cc->counter[COUNTER_steal]=*v->val.integer;
			break;
	}

	return EXIT_SUCCESS;
}

static void debugprint_cpu_info(const char *prefix, struct cpu_info *ci)
{
	int i;
	mp_debug(3, "%s:\n", prefix);
	for(i=0;counter_names[i];i++) {
		mp_debug(3, "%8s: %u\n", counter_names[i], ci->counter[i]);
	}
}

static void fetch_cpu_info(mp_snmp_context *ss, struct cpu_info *ci, int statemask)
{
	if (0 != mp_snmp_walk(ss, SYSTEMSTATS_TABLE, NULL, cpu_callback, ci, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
			mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	if (!raw_found) {
		die(STATE_UNKNOWN, "UNKNOWN: Could not fetch the values at %s. "
			"Please check your config file for SNMP and make sure you have access\n",
			SYSTEMSTATS_TABLE);
	}

	debugprint_cpu_info("From host", ci);

	ci->valid = 1; // We have fetched the value
}

/* not static because utils_base */
void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community>\n",progname);
	printf ("[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-T <type>]\n");
	printf ("([-P snmp version] [-N context] [-L seclevel] [-U secname]\n");
	printf ("[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])\n");
}

static void print_help (void)
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
	printf ("    %s\n", _("total (default)"));
	printf ("    %s\n", _("user"));
	printf ("    %s\n", _("nice"));
	printf ("    %s\n", _("system"));
	printf ("    %s\n", _("idle"));
	printf ("    %s\n", _("iowait"));
	printf ("    %s\n", _("steal"));
	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
static int process_arguments (int argc, char **argv, struct pct_cpu_info *pct)
{
	int c, option;
	int i, x;
	char *optary;

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"type", required_argument, 0, 'T'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

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
				{
					int found_parameter = 0;
					for(i=0;counter_names[i];i++) {
						if(0==strcmp(optarg, counter_names[i])) {
							checktype = i;
							found_parameter = 1;
						}
					}
					if(!found_parameter) {
						die(STATE_UNKNOWN, _("Wrong parameter for -T.\n"));
					}
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

static int load_state(struct cpu_info *ci_current, struct cpu_info *ci_last)
{
	state_data *previous_state;
	char *buffer = NULL;
	char *token;
	int i;

	previous_state = np_state_read();
	if (previous_state == NULL) {
		return -1;
	}

	buffer = strdup(previous_state->data);

	token = strtok(buffer, " ");
	if(!token) goto load_state_error;
	ci_last->valid = strtoul(token, NULL, 10);

	for (i=0;i<COUNTER_NELEMS;i++) {
		token = strtok(NULL, " ");
		if(!token) goto load_state_error;
		ci_last->counter[i] = strtoul(token, NULL, 10);
	}

	token = strtok(NULL, " ");
	if(!token) goto load_state_error;
	ci_current->valid = strtoul(token, NULL, 10);

	for (i=0;i<COUNTER_NELEMS;i++) {
		token = strtok(NULL, " ");
		if(!token) goto load_state_error;
		ci_current->counter[i] = strtoul(token, NULL, 10);
	}
	if(strtok(NULL, " ") != NULL) {
		printf("There should be no more tokens in the buffer");
		goto load_state_error;
	}

	free(buffer);

	debugprint_cpu_info("From file current", ci_current);
	debugprint_cpu_info("From file last", ci_last);
	return 0;

load_state_error:
	free(buffer);
	return 0;
}

static int cpu_info_equals(struct cpu_info *ci_a, struct cpu_info *ci_b)
{
	int i;

	for(i=0;i<COUNTER_NELEMS;i++) {
		if (ci_a->counter[i] != ci_b->counter[i]) {
			return 0;
		}
	}

	return 1;
}
static int save_state(struct cpu_info *ci_current, struct cpu_info *ci_last)
{
	char state_string[4096] = "";
	char param_string[128] = "";
	int i;

	// Save last
	sprintf(param_string, "%u", ci_last->valid);
	strcat(state_string, param_string);
	for (i=0;i<COUNTER_NELEMS;i++) {
		sprintf(param_string, " %u", ci_last->counter[i]);
		strcat(state_string, param_string);
	}
	strcat(state_string, " ");

	// Save current
	sprintf(param_string, "%u", ci_current->valid);
	strcat(state_string, param_string);
	for (i=0;i<COUNTER_NELEMS;i++) {
		sprintf(param_string, " %u", ci_current->counter[i]);
		strcat(state_string, param_string);
	}

	np_state_write_string(0, state_string);

	return 0;
}

/* use macros to avoid typos */
static void calculate_cpu_usage(struct pct_cpu_info *pct, struct cpu_info *current, struct cpu_info *last)
{
	struct cpu_info calc;
	float total = 0;
	int i;

	memset(pct, 0, sizeof(*pct));
	memset(&calc, 0, sizeof(calc));

	for(i=0;i<COUNTER_NELEMS;i++) {
		calc.counter[i] = current->counter[i] - last->counter[i];
		total += calc.counter[i];
	}
	total -= calc.counter[COUNTER_total];
	/* from http://www.net-snmp.org/docs/mibs/ucdavis.html:
	 * This object may sometimes be implemented as the
	 * combination of the 'ssCpuRawWait(54)' and
	 * 'ssCpuRawKernel(55)' counters, so care must be
	 * taken when summing the overall raw counters.
	 *
	 * In case "system" just happens to match up with "wait + kernel",
	 * we'll give a bogus answer, but there's nothing else that hints
	 * about how the snmp daemon behaves, so we have to take a leap
	 * of faith.
	 */
	if (last->counter[COUNTER_system] == (last->counter[COUNTER_iowait] + last->counter[COUNTER_kernel]) ||
		current->counter[COUNTER_system] == (current->counter[COUNTER_iowait] + current->counter[COUNTER_kernel]))
	{
		total -= calc.counter[COUNTER_system];
	}
	debugprint_cpu_info("Fetched (in calculate)", current);
	debugprint_cpu_info("Old (in calculated)", last);
	mp_debug(3, "total ticks: %.0f\n", total);
	debugprint_cpu_info("Calculated", &calc);

	/*
	 * avoid division-by-zero. This happens when the plugin is
	 * run more frequently than the queried server updates its
	 * tick-counters
	 */
	if (!total)
		total = 1;

	for(i=0;i<COUNTER_NELEMS;i++) {
		pct->counter[i] = 100.00 * (float)calc.counter[i] / (float)total;
	}
	// Calculate total seperatly, since it's not available through SNMP natively
	pct->counter[COUNTER_total] = 100.00 - pct->counter[COUNTER_idle];

	if (!pct->counter[COUNTER_user] && !pct->counter[COUNTER_nice] && !pct->counter[COUNTER_system] && !pct->counter[COUNTER_idle] &&
	!pct->counter[COUNTER_iowait] && !pct->counter[COUNTER_kernel] && !pct->counter[COUNTER_steal])
	{
		die(STATE_UNKNOWN, _("UNKNOWN: No difference between states, please re-run the plugin in a few seconds\n"));
	}
}

static void output_message(int result, struct pct_cpu_info *pct)
{
	float current_value = pct->counter[checktype];
	int i;
	printf("%s: %s CPU usage at %.2f%% |", state_text(result), counter_names[checktype], current_value);
	for(i=0;counter_names[i];i++) {
		printf(" %s=%.2f%%", counter_names[i], pct->counter[i]);
		if(checktype == i)
			printf(";%s;%s", warn_str, crit_str);
	}
}

#ifndef MP_TEST_PROGRAM
int main(int argc, char *argv[])
#else
int main_as_in_test_program(int argc, char *argv[])
#endif /* MP_TEST_PROGRAM */
{
	static thresholds *thresh;
	int result = STATE_UNKNOWN, initialize_db;
	struct cpu_info old_current, old_last, fetched;
	struct pct_cpu_info pct;

	memset(&old_current, 0, sizeof(old_current));
	memset(&old_last, 0, sizeof(old_last));
	memset(&fetched, 0, sizeof(fetched));
	memset(&pct, 0, sizeof(pct));

	mp_snmp_init(program_name, 0);
	np_init((char *)progname, argc, argv);

	/* Parse extra opts if any */
	argv=np_extra_opts(&argc, argv, progname);
	if ( process_arguments(argc, argv, &pct) == ERROR )
		usage4 (_("Could not parse arguments"));

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	}

	fetch_cpu_info(ctx, &fetched, ~0); /* get net-snmp cpu data */
	mp_snmp_deinit(program_name); /* deinit */

	/* we must get the old state before we save the new one */
	np_enable_state(NULL, 1);
	initialize_db = load_state(&old_current, &old_last);
	if (!cpu_info_equals(&fetched, &old_current)) {
		memcpy(&old_last, &old_current, sizeof(struct cpu_info));
		memcpy(&old_current, &fetched, sizeof(struct cpu_info));
	}
	save_state(&old_current, &old_last);

	if (initialize_db == -1)
		die(STATE_UNKNOWN, "UNKNOWN: No previous state, initializing database. Re-run the plugin\n");

	if (!old_current.valid || !old_last.valid)
		die(STATE_UNKNOWN, "UNKNOWN: No difference in SNMP counters since first execution, please re-run the plugin in a few seconds\n");

	/**
	 * set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	calculate_cpu_usage(&pct, &old_current, &old_last);

	result = get_status(pct.counter[checktype], thresh);
	output_message(result, &pct);

	printf("\n");

	free(ctx);

	return result;
}
