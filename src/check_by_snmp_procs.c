/**
 * Check system load over snmp
 */

const char *progname = "check_by_snmp_procs";
const char *program_name = "check_by_snmp_procs";
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "config.h"
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include "rbtree.h"

#define DEFAULT_COMMUNITY "public" 	/* only used for help text */
#define DEFAULT_PORT "161"			/* only used for help text */
#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define PROCESS_TABLE "1.3.6.1.2.1.25.4.2.1"
#define PROCESS_SUBIDX_RunIndex 1
#define PROCESS_SUBIDX_RunName 2
#define PROCESS_SUBIDX_RunID 3 /* we don't use this */
#define PROCESS_SUBIDX_RunPath 4
#define PROCESS_SUBIDX_RunParameters 5
#define PROCESS_SUBIDX_RunType 6
#define PROCESS_SUBIDX_RunStatus 7

#define PROCPERF_TABLE "1.3.6.1.2.1.25.5.1.1"
#define PROCPERF_SUBIDX_RunPerfCPU 1
#define PROCPERF_SUBIDX_RunPerfMem 2

enum o_monitortype_t {
	MONITOR_TYPE__NUMBER_OF_PROCESSES,
	MONITOR_TYPE__NUMBER_OF_ZOMBIE_PROCESSES,
	MONITOR_TYPE__PROCESSES_BY_NAME,
	MONITOR_TYPE__NUMBER_OF_PROCESSES_WITH_MEM_AND_CPU
};

static enum o_monitortype_t o_monitortype = MONITOR_TYPE__NUMBER_OF_PROCESSES;
static int o_perfdata = 1; /* perfdata on per default */
static int counter[] = {0,0,0};
static int proc_found = FALSE;
static const char *name_filter = "";

enum process_state {
	PROC_STATE_RUNNING = 1,
	PROC_STATE_RUNNABLE = 2,
	PROC_STATE_NOTRUNNABLE = 3,
	PROC_STATE_INVALID = 4,
};

struct rbtree *all_procs, *interesting;

struct process_state_count {
	int running, runnable, notrunnable, invalid;
};

struct proc_info {
	int Index;
	char *Name;
	int ID;
	char *Path;
	char *Parameters;
	int Type;
	enum process_state Status;
	struct {
		int CPU;
		int Mem;
	} Perf;
	struct proc_info *next;
};

static int proc_compare(const void *a_, const void *b_)
{
	const struct proc_info *a = (struct proc_info *)a_;
	const struct proc_info *b = (struct proc_info *)b_;

	return a->Index - b->Index;
}

static const char *pstate2str(enum process_state pstate)
{
	switch (pstate) {
		case PROC_STATE_RUNNING: return "running";
		case PROC_STATE_RUNNABLE: return "runnable";
		case PROC_STATE_NOTRUNNABLE: return "not runnable";
		case PROC_STATE_INVALID: return "zombie";
	}
	return "(unknown)";
}

/**
 * Helper funtion that counts the total number of different states of the
 * investigated processes.
 */
static int pstate_callback(netsnmp_variable_list *v, void *psc_ptr, void *discard)
{
	struct process_state_count *psc = (struct process_state_count *)psc_ptr;

	proc_found = TRUE;

	switch (*v->val.integer) {
	case PROC_STATE_RUNNING:
		psc->running++;
		break;
	case PROC_STATE_RUNNABLE:
		psc->runnable++;
		break;
	case PROC_STATE_NOTRUNNABLE:
		psc->notrunnable++;
		break;
	case PROC_STATE_INVALID:
		psc->invalid++;
		break;
	}

	return 0;
}

/**
 * Returns the total number of different states the investigated processes are
 * in.
 */
struct process_state_count *check_proc_ret(mp_snmp_context *ss, int statemask)
{
	struct process_state_count *pstate_count = malloc(sizeof(struct process_state_count));
	memset(pstate_count, 0, sizeof(struct process_state_count));
	if (0 != mp_snmp_walk(ss, PROCESS_TABLE ".7", NULL, pstate_callback, pstate_count, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
			mp_snmp_get_peername(ss), mp_snmp_get_errstr(ss));
	}

	mp_debug(3,"Processes: running=%d, runnable=%d, not runnable=%d, invalid=%d\n",
	      pstate_count->running, pstate_count->runnable,
	      pstate_count->notrunnable, pstate_count->invalid);

	if (!proc_found) {
		die(STATE_UNKNOWN, "UNKNOWN: Could not fetch the values at %s. "
			"Please check your config file for SNMP and make sure you have access\n", PROCESS_TABLE);
	}
	return pstate_count;
}

static int proc_info_ret(void *p_, void *discard)
{
	struct proc_info *p = (struct proc_info *)p_;

	mp_debug(2,"################\n");
	mp_debug(2,"  Index: %d\n", p->Index);
	mp_debug(2,"  Name: %s\n", p->Name);
	mp_debug(2,"  Path: %s\n", p->Path);
	mp_debug(2,"  Status: %s\n", pstate2str(p->Status));
	mp_debug(2,"  Parameters: %s\n", p->Parameters);
	mp_debug(2,"  CPU: %d\n", p->Perf.CPU);
	mp_debug(2,"  Mem: %d\n", p->Perf.Mem);

	if (0 == strcmp(p->Name, name_filter))
	{
		counter[0]++;
		counter[1] = counter[1] + p->Perf.CPU;
		counter[2] = counter[2] + p->Perf.Mem;
	}

	return 0;
}

static int parse_state_filter(const char *str)
{
	int filter = 0;
	const char *p;

	if (!str || !*str)
		return 0;

	for (p = str; *p; p++) {
		switch (*p) {
		case 'R': /* running */
			filter |= 1 << PROC_STATE_RUNNING;
			break;
		case 'S': /* sleeping (aka, "runnable") */
			filter |= 1 << PROC_STATE_RUNNABLE;
			break;
		case 'D': /* "dormant", uninterruptable sleep */
			filter |= 1 << PROC_STATE_NOTRUNNABLE;
		case 'Z': /* zombies */
			filter |= 1 << PROC_STATE_INVALID;
		default:
			return -1;
		}
	}

	return filter;
}


static void destroy_proc_info(void *p_)
{
	struct proc_info *p = (struct proc_info *)p;
	if (!p)
		return;
	free(p->Name);
	free(p->Parameters);
	free(p->Path);
	free(p);
}

static int parse_snmp_var(netsnmp_variable_list *v, void *discard1, void *discard2)
{
	struct proc_info *p;
	int pid;

	pid = v->name[11];
	if (v->name[7] == 4 && v->name[10] == 1) {
		/* new process. wohoo */
		p = calloc(1, sizeof(*p));
		p->Index = pid;
		rbtree_insert(all_procs, p);
		return 0;
	}

	p = rbtree_find(all_procs, (struct proc_info *)&pid);
	mp_debug(3, "Found proc_info with id %d\n", p->Index);
	mp_debug(3, "v->name[7]: %d; v->name[10]: %d\n", (int)v->name[7], (int)v->name[10]);
	if (v->name[7] == 5) {
		/* procperf table */
		if (v->name[10] == PROCPERF_SUBIDX_RunPerfCPU) {
			p->Perf.CPU = 1 + *v->val.integer;
		} else if (v->name[10] == PROCPERF_SUBIDX_RunPerfMem) {
			p->Perf.Mem = 1 + *v->val.integer;
		}
		return 0;
	}
	switch (v->name[10]) {
	case PROCESS_SUBIDX_RunID:
		p->ID = *v->val.integer;
		break;
	case PROCESS_SUBIDX_RunName:
		p->Name = strndup((char *)v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunParameters:
		p->Parameters = strndup((char *)v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunPath:
		p->Path = strndup((char *)v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunStatus:
		p->Status = *v->val.integer;
		break;
	}
	return 0;
}

static void fetch_proc_info(mp_snmp_context *ctx)
{
	if (0 != mp_snmp_walk(ctx, ".1.3.6.1.2.1.25.4", ".1.3.6.1.2.1.25.6", parse_snmp_var, NULL, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
			mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community> [-i <name of process>]\n",progname);
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
	printf ("	%s\n", _("total_number_of_processes"));
	printf ("	%s\n", _("total_number_of_zombie_processes"));
	printf ("	%s\n", _("process_by_name"));
	printf (" %s\n", "-i, --indexname=STRING");
	printf ("    %s\n", _("STRING - Name of process to check"));
	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

int main(int argc, char **argv)
{
	static thresholds *thresh;
	int i, x;
	int c, option;
	int process_counter;
	int result = STATE_UNKNOWN;
	mp_snmp_context *ctx;
	struct process_state_count *ptr;
	char *optary;
	char *warn_str = "", *crit_str = "";
	char *state_str = NULL;
	int state_filter;
	int legacy_i, legacy_temp_result = STATE_UNKNOWN;
	char *legacy_warn1 = "", *legacy_warn5 = "", *legacy_warn15 = "";
	char *legacy_crit1 = "", *legacy_crit5 = "", *legacy_crit15 = "";
	char *legacy_token = "";

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"usage", no_argument, 0, 'u'},
		{"perfdata", no_argument, 0, 'f'},
		{"type", required_argument, 0, 'T'},
		{"indexname", required_argument, 0, 'i'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	argv=np_extra_opts (&argc, argv, progname);

	if (argc < 2)
		usage4 (_("Could not parse arguments"));

	optary = calloc(3, ARRAY_SIZE(longopts));
	i = 0;
	optary[i++] = '?';
	for (x = 0; longopts[x].name; x++) {
		struct option *o = &longopts[x];
		if (o->val >= CHAR_MAX || o->val <= 0) {
			continue;
		}
		if (o->val < CHAR_MAX)
			optary[i++] = o->val;
		if (o->has_arg)
			optary[i++] = ':';
		if (o->has_arg == optional_argument)
			optary[i++] = ':';
	}

	mp_debug(2,"optary: %s\n", optary);
	mp_snmp_init("check_by_snmp_procs", 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));
	if (!(all_procs = rbtree_create(proc_compare)))
		die(STATE_UNKNOWN, _("Failed to create tree\n"));

	while (1) {
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;

		if (!mp_snmp_handle_argument(ctx, c, optarg))
			continue;

		switch (c) {
			case 'c':
				crit_str = optarg;
				break;
			case 'w':
				warn_str = optarg;
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
			case 's':
				state_str = optarg;
				break;
			case 'i':
				name_filter = optarg;
				break;
			case 'f':
				o_perfdata = 0;
				break;
			case 'T':
				if (0==strcmp(optarg, "total_number_of_processes")) {
					o_monitortype = MONITOR_TYPE__NUMBER_OF_PROCESSES;
				} else if (0==strcmp(optarg, "total_number_of_zombie_processes")) {
					o_monitortype = MONITOR_TYPE__NUMBER_OF_ZOMBIE_PROCESSES;
				} else if (0==strcmp(optarg, "process_by_name")) {
					o_monitortype = MONITOR_TYPE__PROCESSES_BY_NAME;
				} else if (0==strcmp(optarg, "running_processes_with_average_memory_and_cpu")) {
					o_monitortype = MONITOR_TYPE__NUMBER_OF_PROCESSES_WITH_MEM_AND_CPU;
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
		printf("%s: %s: ", state_text(STATE_UNKNOWN), _("Unhandled arguments present"));
		for (i = optind - 1; i < argc; i++) {
			printf("%s%s", argv[i], i == argc - 1 ? "\n" : ", ");
		}
		exit(STATE_UNKNOWN);
	}

	if (o_monitortype != MONITOR_TYPE__NUMBER_OF_PROCESSES_WITH_MEM_AND_CPU)
		set_thresholds(&thresh, warn_str, crit_str);

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	};

	state_filter = parse_state_filter(state_str);
	if (state_filter < 0) {
		die(STATE_UNKNOWN, _("Invalid state filter string: %s\n"), state_str);
	}

	fetch_proc_info(ctx);
	mp_debug(2,"Traversing %d nodes\n", rbtree_num_nodes(all_procs));

	switch (o_monitortype) {
		case MONITOR_TYPE__NUMBER_OF_PROCESSES:
			ptr = check_proc_ret(ctx, ~0);
			process_counter = ptr->runnable + ptr->running + ptr->notrunnable + ptr->invalid;
			result = get_status(process_counter, thresh);
			printf("%s: %d process(es) ", state_text(result), process_counter);
			if (o_perfdata == 1) {
				printf("|'Processes'=%d;%s;%s", process_counter, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__NUMBER_OF_ZOMBIE_PROCESSES:
			ptr = check_proc_ret(ctx, ~0);
			result = get_status(ptr->invalid, thresh);
			printf("%s: %d zombie process(es) ", state_text(result), ptr->invalid);
			if (o_perfdata == 1) {
				printf("|'Zombie processes'=%d;%s;%s", ptr->invalid, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__PROCESSES_BY_NAME:
			rbtree_traverse(all_procs, proc_info_ret, NULL, rbinorder);
			rbtree_destroy(all_procs, destroy_proc_info);
			result = get_status(counter[0], thresh);
			printf("%s: %d %s process(es) ", state_text(result), counter[0], name_filter);
			if (o_perfdata == 1) {
				printf("|'%s'=%d;%s;%s", name_filter, counter[0], warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__NUMBER_OF_PROCESSES_WITH_MEM_AND_CPU:
			rbtree_traverse(all_procs, proc_info_ret, NULL, rbinorder);
			rbtree_destroy(all_procs, destroy_proc_info);
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
			legacy_temp_result = get_status(counter[0], thresh);
			result = max_state(legacy_temp_result, result);

			set_thresholds(&thresh, legacy_warn5, legacy_crit5);
			legacy_temp_result = get_status(counter[1], thresh);
			result = max_state(legacy_temp_result, result);

			set_thresholds(&thresh, legacy_warn15, legacy_crit15);
			legacy_temp_result = get_status(counter[2], thresh);
			result = max_state(legacy_temp_result, result);

			printf("%s: %d %s process(es) ", state_text(result), counter[0], name_filter);
			if (o_perfdata == 1) {
				printf("|'%s'=%d;%s;%s '%s'=%d;%s;%s '%s'=%d;%s;%s",
						name_filter, counter[0], legacy_warn1, legacy_crit1,
						"Memory", counter[1], legacy_warn5, legacy_crit5,
						"CPU", counter[2], legacy_warn15, legacy_crit15);
			}
			break;
		default:
			usage4 (_("Could not parse arguments for -T"));
			break;
	}
	mp_snmp_deinit("check_by_snmp_procs");
	printf("\n");

	free(ctx);

	return result;
}
