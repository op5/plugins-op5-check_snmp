/**
 * Check system load over snmp
 */

const char *progname = "check_snmp_procs";
const char *program_name = "check_snmp_procs";
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "config.h"
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <naemon/naemon.h>

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

static thresholds *thresh;

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

static int procs;

static int pstate_callback(netsnmp_variable_list *v, void *psc_ptr, void *discard)
{
	struct process_state_count *psc = (struct process_state_count *)psc_ptr;

	procs++;

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

static int check_proc_states(mp_snmp_context *ss, int statemask)
{
	int i;
	struct process_state_count pstate_count;

	memset(&pstate_count, 0, sizeof(pstate_count));
	mp_snmp_walk(ss, PROCESS_TABLE ".7", NULL, pstate_callback, &pstate_count, NULL);
	printf("Processes: running=%d, runnable=%d, not runnable=%d, invalid=%d\n",
	      pstate_count.running, pstate_count.runnable, pstate_count.notrunnable, pstate_count.invalid);
}

static struct proc_info *query_process(mp_snmp_context *ctx, int k)
{
	netsnmp_pdu *pdu, *response = NULL;
	netsnmp_variable_list *v;
	int mask=0;
	struct proc_info *p;
	int error = 0, count = 0;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!pdu) {
		return NULL;
	}

	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunStatus);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunName);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunParameters);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunPath);
	mp_snmp_add_keyed_subtree(pdu, PROCESS_TABLE, mask, k);
	mask = 0;
	MP_SNMP_PDU_MASK_ADD(mask, PROCPERF_SUBIDX_RunPerfCPU);
	MP_SNMP_PDU_MASK_ADD(mask, PROCPERF_SUBIDX_RunPerfMem);
	mp_snmp_add_keyed_subtree(pdu, PROCPERF_TABLE, mask, k);
	if (mp_snmp_query(ctx, pdu, &response)) {
		die(STATE_UNKNOWN, _("Failed to fetch variables for process %d\n"), k);
	}
	if (!(p = calloc(1, sizeof(*p)))) {
		snmp_free_pdu(response);
		snmp_free_pdu(pdu);
		die(STATE_UNKNOWN, _("Failed to allocate memory"));
	}

	for (v = response->variables; v; v = v->next_variable, count++) {
		int is_perf;
		if (!mp_snmp_is_valid_var(v)) {
			error++;
			continue;
		}
		if (v->name[7] == 5) {
			/* procperf table */
			if (v->name[10] == PROCPERF_SUBIDX_RunPerfCPU) {
				p->Perf.CPU = 1 + *v->val.integer;
			} else if (v->name[10] == PROCPERF_SUBIDX_RunPerfMem) {
				p->Perf.Mem = 1 + *v->val.integer;
			}
			continue;
		}
		switch (v->name[10]) {
			case PROCESS_SUBIDX_RunID:
				p->ID = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunIndex:
				p->Index = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunName:
				p->Name = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunParameters:
				p->Parameters = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunPath:
				p->Path = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunStatus:
				p->Status = *v->val.integer;
				break;
		}
	}
	mp_debug(2, "count: %d\n", count);
	snmp_free_pdu(response);
	return p;
}

static int print_proc_info(void *p_, void *discard)
{
	struct proc_info *p = (struct proc_info *)p_;

	printf("################\n");
	printf("  Index: %d\n", p->Index);
	printf("  Name: %s\n", p->Name);
	printf("  Path: %s\n", p->Path);
	printf("  Status: %s\n", pstate2str(p->Status));
	printf("  Parameters: %s\n", p->Parameters);
	printf("  CPU: %d\n", p->Perf.CPU);
	printf("  Mem: %d\n", p->Perf.Mem);

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
	print_variable(v->name, v->name_length, v);
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
		p->Name = strndup(v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunParameters:
		p->Parameters = strndup(v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunPath:
		p->Path = strndup(v->val.string, v->val_len);
		break;
	case PROCESS_SUBIDX_RunStatus:
		p->Status = *v->val.integer;
		break;
	}
	return 0;
}

static void fetch_proc_info(mp_snmp_context *ctx)
{
	mp_snmp_walk(ctx, ".1.3.6.1.2.1.25.4", ".1.3.6.1.2.1.25.6", parse_snmp_var, NULL, NULL);
}

void print_usage(void)
{
	printf("check_snmp_procs -H <host> -C <community> (etc...)\n");
	//return 0;
}

int main(int argc, char **argv)
{
	int i, x;
	int c, err, option;
	netsnmp_session session, *ss;
	mp_snmp_context *ctx;
	struct proc_info *p;
	char *optary;
	char *warn_str = NULL, *crit_str = NULL;
	char *state_str = NULL;
	int state_filter;
	const char *name_filter;
	const char *ereg_name_filter;
	bitmap *bm;

	static struct option longopts[] = {
		{"timeout", required_argument, 0, 't'},
		{"warning", required_argument, 0, 'w'},
		{"critical", required_argument, 0, 'c'},
		{"state", required_argument, 0, 's'},
		{"host", required_argument, 0, 'H'},
		{"metric", required_argument, 0, 'm'},
		{"command", required_argument, 0, 'O'},
		{"vsz", required_argument, 0, 'z'},
		{"ereg-argument-array", required_argument, 0, CHAR_MAX+1},
		{"input-file", required_argument, 0, CHAR_MAX+2},
		{"elapsed", required_argument, 0, 'e'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	/* XXX REMOVE WHEN READY */
	mp_verbosity = 3;

	optary = calloc(1, 3 + (3 * ARRAY_SIZE(longopts)));
	i = 0;
	optary[i++] = '+';
	optary[i++] = '?';
	for (x = 0; longopts[x].name; x++) {
		struct option *o = &longopts[x];
		if (o->val >= CHAR_MAX || o->val <= 0) {
			continue;
		}
		if (bitmap_isset(bm, o->val)) {
			printf("###\n### %c is a double option, doofus!\n###\n", c);
			exit(1);
		}
		bitmap_set(bm, o->val);
		if (o->val < CHAR_MAX)
			optary[i++] = o->val;
		if (o->has_arg)
			optary[i++] = ':';
		if (o->has_arg == optional_argument)
			optary[i++] = ':';
	}

	bitmap_destroy(bm);
	printf("optary: %s\n", optary);
	mp_snmp_init("check_snmp_procs", 0);
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
		case 's':
			state_str = optarg;
			break;
		case 'n':
			name_filter = optarg;
			break;
		case CHAR_MAX + 1:
			ereg_name_filter = optarg;
			break;
		}
	}
	free(optary);

	set_thresholds(&thresh, warn_str, crit_str);
	mp_snmp_finalize_auth(ctx);
	state_filter = parse_state_filter(state_str);
	if (state_filter < 0) {
		die(STATE_UNKNOWN, _("Invalid state filter string: %s\n"), state_str);
	}

#if 0
	bm = filter_processes(state_filter, name_filter, ereg_name_filter);
	bm = bitmap_create(65536); /* 8kb. Will grow if pid > 65536 */
	if (state_filter) {
		filter_states(ctx, bm, state_filter);
	}
	if (name_filter) {
		filter_names(ctx, bm, name_filter);
	}
#endif

	fetch_proc_info(ctx);
	printf("Traversing %d nodes\n", rbtree_num_nodes(all_procs));
	rbtree_traverse(all_procs, print_proc_info, NULL, rbinorder);
	rbtree_destroy(all_procs, destroy_proc_info);
	return 0;
	if (1) {
		p = query_process(ctx, 1);
		print_proc_info(p, NULL);
		destroy_proc_info(p);
	}
	procs = 0;
	if (1) {
		check_proc_names(ctx);
		printf("procs: %d\n", procs);
	}
	procs = 0;
	if (1) {
		check_proc_states(ctx, ~0);
		printf("procs: %d\n", procs);
	}
	mp_snmp_deinit("check_snmp_procs");

	return 0;
}
