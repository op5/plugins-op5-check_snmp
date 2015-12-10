/**
 * Run "extend" commands via snmp
 */

const char *progname = "check_by_snmp_extend";
const char *program_name = "check_by_snmp_extend";
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "config.h"
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include "rbtree.h"

/* oid slot that decides which type of var this is */
#define NSCONFIG_TYPE_OFFSET 12
/* oid part where name starts (with 'len') */
#define NSCONFIG_NAME_OFFSET 13

#define DEFAULT_COMMUNITY "public" 	/* only used for help text */
#define DEFAULT_PORT "161"			/* only used for help text */
#define DEFAULT_TIME_OUT 15			/* only used for help text */


#define nsExtendConfigTable ".1.3.6.1.4.1.8072.1.3.2.2.1"
#define CONFIG_BASEOID_LEN 12

#define NSCONFIG_SUBIDX_Command 2
#define NSCONFIG_SUBIDX_Args 3
#define NSCONFIG_SUBIDX_Input 4
#define NSCONFIG_SUBIDX_CacheTime 5
#define NSCONFIG_SUBIDX_ExecType 6
#define NSCONFIG_SUBIDX_RunType 7
#define NSCONFIG_SUBIDX_Storage 20
#define NSCONFIG_SUBIDX_Status 21

#define NSEXTEND_TYPE_OID_OFFSET 12
#define NSEXTEND_OUTPUT 2
#define NSEXTEND_RESULT 4
/* these need to get \"name\" appended to them, with length */
#define BASEOID_nsExtendOutputFull  ".1.3.6.1.4.1.8072.1.3.2.3.1.2"
#define BASEOID_nsExtendResult ".1.3.6.1.4.1.8072.1.3.2.3.1.4"
#define BASEOID_LEN 13


struct extend_config {
	char *name;
	char *Command;
	char *Args;
	char *Input;
	int CacheTime;
	int ExecType;
	int RunType;
	int Storage;
	int Status;
};


struct exec_info {
	int Result;
	char *Output;
};

static void debug_print_one_result(int level, struct exec_info *ei)
{
	mp_debug(level, "result: %d\n", ei->Result);
	mp_debug(level, "output: %s\n", ei->Output);
}

static int parse_snmp_var(netsnmp_variable_list *v, struct exec_info *ei)
{
	switch (v->name[NSEXTEND_TYPE_OID_OFFSET]) {
		case NSEXTEND_OUTPUT:
			ei->Output = strndup((char *)v->val.string, v->val_len);
			break;
		case NSEXTEND_RESULT:
			ei->Result = *v->val.integer;
			break;
	}

	return 0;
}

static int fetch_result(mp_snmp_context *ctx, const char *name, struct exec_info *ei)
{
	struct mp_snmp_oid output, result;
	netsnmp_variable_list *v;
	netsnmp_pdu *response = NULL;
	int ret;

	result.len = output.len = MAX_OID_LEN;
	snmp_parse_oid(BASEOID_nsExtendOutputFull, output.id, &output.len);
	snmp_parse_oid(BASEOID_nsExtendResult, result.id, &result.len);
	mp_snmp_asciioid_append(&result, name);
	mp_snmp_asciioid_append(&output, name);
	mp_debug(1, "Fetching %s\n", mp_snmp_oid2str(output.id, output.len));
	mp_debug(1, "Fetching %s\n", mp_snmp_oid2str(result.id, result.len));
	ret = mp_snmp_getl(ctx, &response, &result, &output, NULL);
	if (ret < 0 || !response)
		return -1;
	for (v = response->variables; v; v = v->next_variable) {
		if (!mp_snmp_is_valid_var(v)) {
			char *errstr = mp_snmp_var_errstr(v, 0);
			ei->Result = STATE_UNKNOWN;
			asprintf(&ei->Output, "%s: %s: %s: %s", progname, state_text(STATE_UNKNOWN),
				_("Failed to fetch snmp data"), errstr);
			free(errstr);
			break;
		} else {
			if ((ret = parse_snmp_var(v, ei)))
				break;
		}
	}
	debug_print_one_result(1, ei);
	snmp_free_pdu(response);

	return ret < 0 ? -1 : 0;
}

static int list_walker(netsnmp_variable_list *v, void *tree_, void *discard)
{
	struct rbtree *tree = (struct rbtree *)tree_;
	char *name;
	struct extend_config *ec, lookup;

	name = lookup.name = mp_snmp_asciioid_extract(&v->name[NSCONFIG_NAME_OFFSET]);
	mp_debug(3, "Found var %d for extension %s\n", (int)v->name[NSCONFIG_TYPE_OFFSET], name);
	if (!(ec = rbtree_find(tree, &lookup))) {
		ec = calloc(1, sizeof(*ec));
		ec->name = name;
		rbtree_insert(tree, ec);
	} else {
		/* avoid leaking */
		free(name);
		name = ec->name;
	}

	switch (v->name[NSCONFIG_TYPE_OFFSET]) {
		case NSCONFIG_SUBIDX_Command:
			ec->Command = strndup((char *)v->val.string, v->val_len);
			break;
		case NSCONFIG_SUBIDX_Args:
			ec->Args = strndup((char *)v->val.string, v->val_len);
			break;
		case NSCONFIG_SUBIDX_Input:
			ec->Input = strndup((char *)v->val.string, v->val_len);
			break;
		case NSCONFIG_SUBIDX_CacheTime:
			ec->CacheTime = *v->val.integer;
			break;
		case NSCONFIG_SUBIDX_ExecType:
			ec->ExecType = *v->val.integer;
			break;
		case NSCONFIG_SUBIDX_RunType:
			ec->ExecType = *v->val.integer;
			break;
		case NSCONFIG_SUBIDX_Storage:
			ec->Storage = *v->val.integer;
			break;
		case NSCONFIG_SUBIDX_Status:
			ec->Status = *v->val.integer;
			break;
	}

	return 0;
}

static int extend_config_cmp(const void *a_, const void *b_)
{
	const struct extend_config *a = (struct extend_config *)a_;
	const struct extend_config *b = (struct extend_config *)b_;
	return strcmp(a->name, b->name);
}

static int print_one_extend_config(void *ec_, void *discard)
{
	struct extend_config *ec = (struct extend_config *)ec_;
	printf("%s %s %s\n", ec->name, ec->Command, ec->Args);
	return 0;
}

static void destroy_extend_config(void *ec_)
{
	struct extend_config *ec = (struct extend_config *)ec_;

	free(ec->name);
	free(ec->Command);
	free(ec->Args);
	free(ec->Input);
	free(ec);
}

static void list_all_commands(mp_snmp_context *ctx)
{
	struct rbtree *tree;

	if (!(tree = rbtree_create(extend_config_cmp))) {
		printf("%s: %s: %s\n", progname, state_text(STATE_UNKNOWN),
		       _("Unable to allocate memory for extend storage"));
		exit(STATE_UNKNOWN);
	}

	if (0 != mp_snmp_walk(ctx, nsExtendConfigTable, NULL, list_walker, tree, NULL)) {
		printf("%s: Failed to list processes: %s\n", progname, mp_snmp_get_errstr(ctx));
		exit(STATE_UNKNOWN);
	}
	rbtree_traverse(tree, print_one_extend_config, NULL, rbinorder);
	rbtree_destroy(tree, destroy_extend_config);
}

void print_usage (void)
{
	printf("%s\n", _("Usage:"));
	printf("%s [-i <name of command>|--list]\n", progname);
	mp_snmp_argument_usage();
}

void print_help (void)
{
	print_revision (progname, NP_VERSION);
	printf ("%s\n", _("Run remote commands via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf (" %s\n", "-i, --indexname=STRING");
	printf ("    %s\n", _("STRING - Name of remote command to run"));
	mp_snmp_argument_help();
}

int main(int argc, char **argv)
{
	mp_snmp_context *ctx;
	int c, option, x, i;
	int result = STATE_UNKNOWN;
	int list_commands = 0;
	char *optary;
	char *name = NULL;
	struct exec_info ei = { 0, NULL };

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"indexname", required_argument, 0, 'i'},
		{"list", no_argument, 0, 'l'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	argv = np_extra_opts (&argc, argv, progname);
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
	mp_snmp_init(progname, 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("%s: Failed to create snmp context\n"), progname);

	while (1) {
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;

		if (!mp_snmp_handle_argument(ctx, c, optarg))
			continue;

		switch (c) {
			case 'l':
				list_commands = 1;
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
			case 'i':
				name = optarg;
				break;
			default:
				exit(STATE_UNKNOWN);
				break;
		}
	}
	free(optary);

	if (optind != argc) {
		printf("%s: %s: %s\n", progname, state_text(STATE_UNKNOWN), _("Unhandled arguments present"));
		for (i = optind - 1; i < argc; i++) {
			printf("%s%s", argv[i], i == argc - 1 ? "\n" : ", ");
		}
		exit(STATE_UNKNOWN);
	}

	if (!list_commands && (!name || !*name)) {
		printf("%s: %s %s\n", progname, state_text(STATE_UNKNOWN), _("Not listing and no exec name given."));
		exit(STATE_UNKNOWN);
	}

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	};

	if (list_commands) {
		list_all_commands(ctx);
		exit(STATE_OK);
	}

	/* if fetching went well, just dump the output and we're done */
	if (!fetch_result(ctx, name, &ei)) {
		printf("%s\n", ei.Output);
		result = ei.Result;
		free(ei.Output);
	} else {
		printf("%s: %s: Failed to fetch SNMP data: %s\n", progname,
		       state_text(STATE_UNKNOWN), mp_snmp_get_errstr(ctx));
		result = STATE_UNKNOWN;
	}

	mp_snmp_destroy_context(ctx);
	mp_snmp_deinit(progname);

	return result;
}
