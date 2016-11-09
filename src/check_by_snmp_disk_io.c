/**
 * Check disk read/write over snmp
 */
const char *progname = "check_by_snmp_disk_io";
const char *program_name = "check_by_snmp_disk_io"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "rbtree.h"
#include <regex.h>

#define REGEX_FLAGS (REG_EXTENDED | REG_NOSUB | REG_NEWLINE)

#define DEFAULT_TIME_OUT 15 /* only used for help text */

#define DISKIOTABLE     ".1.3.6.1.4.1.2021.13.15.1.1" /* hrStorageEntry */
#define DISKIO_Index    1
#define DISKIO_Device   2
#define DISKIO_NRead    3
#define DISKIO_NWritten 4
#define DISKIO_Reads    5
#define DISKIO_Writes   6
#define DISKIO_LA1      9
#define DISKIO_LA5      10
#define DISKIO_LA15     11

#define DISKIO_ALL ( \
	(1 << DISKIO_Device) | \
	(1 << DISKIO_NRead) | \
	(1 << DISKIO_NWritten) | \
	(1 << DISKIO_Reads) | \
	(1 << DISKIO_Writes))// | \
//	(1 << DISKIO_LA1) | \
//	(1 << DISKIO_LA5) | \
//	(1 << DISKIO_LA15))

enum {
	COUNTER_nread = 0,
	COUNTER_nwritten,
	COUNTER_reads,
	COUNTER_writes,
	load
};

#define COUNTER_NELEMS (((int)COUNTER_writes)+1)

static const char *counter_names[] = {
	"nread",    /* bytes read since boot */
	"nwritten", /* bytes written since boot */
	"reads",    /* read accesses since boot */
	"writes",   /* write accesses since boot */
	NULL
};

static int list_disks;
static int debugtime = 0;
static int checktype = COUNTER_nread;
static char *warn_str = "", *crit_str = "";
static char save_string[4096] = "";
static char thresholdunit = '%';
static struct rbtree *filter_tree, *previous_tree;
static int discard_default_filters;
static int sum_all_disks;
static int include_filters, exclude_filters;
time_t cur_time, pre_time, dif_time;
static char filter_charmap_magic[255];

struct di_result {
	char *uom;
	thresholds *thresh;
	thresholds *load1;
	thresholds *load5;
	thresholds *load15;
	struct rbtree *critical, *warning;
};

struct disk_info {
	unsigned int Index;
	char *Device;
	unsigned int counter[COUNTER_NELEMS]; /* counters */
	unsigned int LA1;
	unsigned int LA5;
	unsigned int LA15;

	unsigned int have_vars;

	unsigned int calc_counter[COUNTER_NELEMS]; /* calculated counters */
	/* book-keeping for filters */
	int filter_in;
	int filter_out;
};

struct disk_filter {
	unsigned int order;
	int exclude;
	int what;
	int how;
	char *what_str; /* for debugging */

	double value;
	char *str;
	regex_t preg;
};

#define FILTER_Type 1
#define FILTER_Name 2
#define FILTER_Size 3
#define FILTER_AllocationUnits 4
#define FILTER_Used 5

#define FILTER_EQ '='
#define FILTER_GT '>'
#define FILTER_LT '<'
#define FILTER_GT_PLUS '+'
#define FILTER_LT_MINUS '-'
#define FILTER_REGEX '~'
#define FILTER_EXCLUDE 1024
#define FILTER_HOW(t) (t & 0xff)
#define FILTER_ACTION(t) (t & 1024)

struct disk_info *disk_info_new(void) {
	struct disk_info *di = calloc(1, sizeof(struct disk_info));
	return di;
}

void disk_info_destroy(struct disk_info *di) {
	if (di == NULL) {
		return;
	}

	free(di->Device);
	free(di);
}

/**
 * Sets the device name for disk_info when loading the previous disk_info struct
 * from the file.
 */
void disk_info_set_device(struct disk_info *di, const char *Device) {
	free(di->Device);
	di->Device = strdup(Device);
}

/*
 * Parse a disk filter string.
 * How we parse it depends on what we're filtering on.
 * FILTER_Type: list of disk types.
 * FILTER_Name: string
 * FILTER_Size: human-y representation of bytes
 * FILTER_AllocationUnits: human-y representation of bytes
 * FILTER_Used: human-y representation of bytes
 * FILTER_Avail: human-y representation of bytes
 */
static struct disk_filter *parse_filter(
	char *what_str,
	int flags,
	const char *orig_str
) {
	static unsigned int order = 0;
	struct disk_filter *f;

	mp_debug(2, "Parsing '%s' filter from '%s' (flags: %d)\n",
		what_str, orig_str, flags);

	f = calloc(1, sizeof(*f));
	f->what = FILTER_Name;
	f->what_str = strdup(what_str);
	f->exclude = 1;
	f->order = order++;
	f->str = strdup(orig_str);

	include_filters += FILTER_ACTION(flags) != FILTER_EXCLUDE;
	exclude_filters += FILTER_ACTION(flags) == FILTER_EXCLUDE;
	if (FILTER_HOW(flags) == FILTER_GT_PLUS) {
		flags = FILTER_ACTION(flags) | FILTER_GT;
	}
	if (FILTER_HOW(flags) == FILTER_LT_MINUS) {
		flags = FILTER_ACTION(flags) | FILTER_LT;
	}
	f->how = flags;

	switch (f->what) {
	 case FILTER_Name:
		if (FILTER_HOW(flags) == FILTER_REGEX) {
			int ret = regcomp(&f->preg, f->str, REGEX_FLAGS);
			if (ret) {
				char errbuf[1024];
				regerror(ret, &f->preg, errbuf, sizeof(errbuf));
				die(STATE_UNKNOWN, _("Failed to compile regular expression: "
					"%s\n"), errbuf);
			}
		}
		break;
	}
	return f;
}

static void add_filter(char *what_str, int flags, const char *orig_str)
{
	struct disk_filter *filter;

	filter = parse_filter(what_str, flags, orig_str);
	if (!filter) {
		die(STATE_UNKNOWN, _("Failed to parse %s filter from '%s'\n"),
			what_str, orig_str);
	}
	rbtree_insert(filter_tree, filter);
}

/* sort exclude-filters first */
static int filter_compare(const void *a_, const void *b_)
{
	struct disk_filter *a = (struct disk_filter *)a_;
	struct disk_filter *b = (struct disk_filter *)b_;

	return a->order - b->order;
}

static int match_filter_value(int flags, double a, double b)
{
	int match = 0;

	mp_debug(2, "      checking if %.2f %c %.2f\n", a, FILTER_HOW(flags), b);
	switch (FILTER_HOW(flags)) {
	 case FILTER_EQ:
		match = a == b;
		break;
	 case FILTER_GT: case FILTER_GT_PLUS:
		match = a > b;
		break;
	 case FILTER_LT: case FILTER_LT_MINUS:
		match = a < b;
		break;
	 default:
		return 0;
	}

	return match;
}

static int filter_one_disk(void *a_, void *b_)
{
	struct disk_filter *f = (struct disk_filter *)a_;
	struct disk_info *di = (struct disk_info *)b_;
	int match = 0;
	double value = 0.0;

	mp_debug(2, "   checking %sclude filter '%s%c%s' against %s\n",
	         FILTER_ACTION(f->how) == FILTER_EXCLUDE ? "ex" : "in",
	         f->what_str, FILTER_HOW(f->how), f->str, di->Device);
	switch (f->what) {
	 case FILTER_Name:
		if (FILTER_HOW(f->how) == FILTER_REGEX) {
			int ret = regexec(&f->preg, di->Device, 0, NULL, 0);
			if (!ret) {
				match = 1;
			}
		} else if (!strcmp(di->Device, f->str)) {
			match = 1;
		}
		break;
	}

	if (value)
		match = match_filter_value(f->how, value, f->value);

	if (match) {
		mp_debug(2, "      It's a match\n");
		if (FILTER_ACTION(f->how) == FILTER_EXCLUDE) {
			di->filter_out++;
		} else {
			di->filter_in++;
		}
	} else {
		mp_debug(2, "      No match\n");
	}
	return 0;
}

static void debugprint_disk_info(
	const char *prefix,
	struct disk_info *di,
	int lvl
) {
	int i;
	mp_debug(lvl, "%s:\n", prefix);
	mp_debug(lvl, "Index: %d Device: %s \n", di->Index, di->Device);

	for(i=0;counter_names[i];i++) {
		mp_debug(lvl, "%8s: %u\n", counter_names[i], di->counter[i]);
	}
	for(i=0;counter_names[i];i++) {
		mp_debug(lvl, "%8s: %u\n", counter_names[i], di->calc_counter[i]);
	}

	mp_debug(lvl, "load1: %d load5: %d load15: %d\n",
		di->LA1, di->LA5, di->LA15);
}

/**
 * Calculate the difference of counter values per second between runs
 */
static int calc_disk_read_write(void *di_ptr, void *the_tree)
{
	struct disk_info locator, *dic;
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct rbtree *t = (struct rbtree *)the_tree;
	int i;

	locator.Index = di->Index;

	dic = rbtree_find(t, (struct disk_info *)&locator);

	if (!dic) {
		die(STATE_UNKNOWN,
			_("Unable to locate disk index %d from previous run.\n"),
			locator.Index);
	}

	if (dif_time <= 0) {
		die(STATE_UNKNOWN,
			_("Time error, wait at least 1 second between checks\n"));
	}

	/* Calculate the byte difference per second */
	for(i=0;counter_names[i];i++) {
		di->calc_counter[i] = (di->counter[i] - dic->counter[i])/dif_time;
	}

	return 0;
}

static int filter_disks(void *di_ptr, void *to_tree)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct rbtree *target_tree = (struct rbtree *)to_tree;

	mp_debug(3, "Checking disk '%s' against filters\n",
		di->Device ? di->Device : "(noname; will be skipped)");
	if (!di->Device) {
		debugprint_disk_info("From filter disk", di_ptr, 3);
		die(STATE_UNKNOWN, _("Failed to read description for storage unit with"
			" index %d. Please check your SNMP configuration\n"), di->Index);
	}
	if (!di->filter_out && (di->have_vars & DISKIO_ALL) != DISKIO_ALL) {
		mp_debug(3, "have_vars: %u; HRSTORAGE_ALL: %u; delta: %u\n",
			di->have_vars, DISKIO_ALL, di->have_vars ^ DISKIO_ALL);
		die(STATE_UNKNOWN, _("Failed to read data for storage unit %d (%s). "
			"Please check your SNMP configuration\n"),
		    di->Index, di->Device ? di->Device : "NULL");
	}

	if (!di->filter_out && filter_tree && rbtree_num_nodes(filter_tree)) {
		rbtree_traverse(filter_tree, filter_one_disk, di, rbinorder);
	}
	mp_debug(3, "   selected by %d/%d filters\n",
		di->filter_in, include_filters);
	mp_debug(3, "   discarded by %d/%d filterrs\n",
		di->filter_out, exclude_filters);
	if (!di->filter_out && (!include_filters || di->filter_in)) {
		mp_debug(3, "   +++ selected\n");
		rbtree_insert(target_tree, di);
	} else {
		mp_debug(3, "   --- discarded\n");
	}

	return 0;
}

void print_usage(void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s [--list] [-D] [-T <type_of_check>]\n", progname);
	printf ("  %s", _("[-w <warn_range>] "));
    printf ("%s\n", _("[-c <crit_range>]"));
	mp_snmp_argument_usage();
}

static void print_help(void)
{
	print_revision(progname, NP_VERSION);
	printf ("%s\n", _("Check status of remote machines and obtain system "
		"information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf ( UT_WARN_CRIT_RANGE);
	printf (" %s\n", "-m, --uom");
	printf ("    %s\n", _("Unit of measurement for warning/critical range "));
	printf ("    %s\n", _("%, b, kib, mib, gib, tib, pib, eib, zib or yib"));
	printf ("    %s\n", _("default: b (counter for reads/writes, % for load)"));
	printf (" %s\n", "-T, --type-of-check <string>");
	printf ("    %s\n", _("nread    - Bytes read from this device (default)"));
	printf ("    %s\n", _("nwritten - Bytes written"));
	printf ("    %s\n", _("reads    - Number of read accesses"));
	printf ("    %s\n", _("writes   - Number of write accesses"));
	printf ("    %s\n", _("load     - Percent average load, uses three"));
	printf ("        %s\n", _("arguments for thresholds (<int>,<int>,<int>)"));
	printf (" %s\n", "-l, --list");
	printf ("    %s\n", _("List all storage units selected by your filter"));
	printf (" %s\n", "-D, --discard-default-filters");
	printf ("    %s\n", _("Discard default filters"));
	printf (" %s\n", "-e, --include-regex <regex>");
	printf ("    %s\n", _("Regular expression to match for inclusion"));
	printf (" %s\n", "-E, --exclude-regex <regex>");
	printf ("    %s\n", _("Regular expression to match for exclusion"));
	printf (" %s\n", "-i, --include-name <string>");
	printf ("    %s\n", _("Name of storage unit to include"));
	printf (" %s\n", "-I, --exclude-name <string>");
	printf ("    %s\n", _("Name of storage unit to exclude"));
	printf (" %s\n", "-q, --debug-pretime <int>");
	printf ("    %s\n", _("This is only used for testing and debugging"));
	printf (" %s\n", "-Q, --debug-curtime <int>");
	printf ("    %s\n", _("This is only used for testing and debugging"));

	mp_snmp_argument_help();
	printf ("Notes on filters:\n");
	printf ("  * exclude filters always trump include filters\n");
	printf ("  * if no include filters are present, all units not excluded ");
	printf ("are included\n");
	printf ("  * --list prints all selected units\n");
	printf ("  * Default filter excludes disks with the names ram and loop\n");
	printf ("  * <numcomparison> is of the form '+400' or '-400', meaning\n");
	printf ("      'greater than or equal to 400' and 'less than ");
	printf ("or equal to 400', respectively\n");
	printf ("  * Any number of filters can be chained together\n");
}

/* process command-line arguments */
static int process_arguments(mp_snmp_context *ctx, int argc, char **argv)
{
	int c, option, parsed = 0;
	int i, x;
	char *optary;
	static struct option longopts[] = {
		STD_LONG_OPTS,
		{ "uom", required_argument, 0, 'm'},
		{ "type-of-check", required_argument, 0, 'T' },
		{ "list", no_argument, 0, 'l' },
		{ "discard-default-filters", no_argument, 0, 'D' },
		{ "include-name", required_argument, 0, 'i' },
		{ "exclude-name", required_argument, 0, 'I' },
		{ "include-regex", required_argument, 0, 'e' },
		{ "exclude-regex", required_argument, 0, 'E' },
		{ "debug-pretime", required_argument, 0, 'q' },
		{ "debug-curtime", required_argument, 0, 'Q' },
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	if (argc < 2)
		usage4 (_("Could not parse arguments"));

	/* these are needed when we process size filters */
	filter_charmap_magic[FILTER_EQ] = FILTER_EQ;
	filter_charmap_magic[FILTER_GT] = FILTER_GT;
	filter_charmap_magic[FILTER_GT_PLUS] = FILTER_GT_PLUS;
	filter_charmap_magic[FILTER_LT] = FILTER_LT;
	filter_charmap_magic[FILTER_LT_MINUS] = FILTER_LT_MINUS;

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
	mp_debug(3,"optary: %s\n", optary);

	while (1) {
		parsed++;
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;
		if (!mp_snmp_handle_argument(ctx, c, optarg))
			continue;

		switch (c) {
			case 'D':
				discard_default_filters = 1;
				break;
			case 'T':
				if (0 == strcmp(optarg, "load")) {
					checktype = load;
					break;
				}
				for (i = 0; i<COUNTER_NELEMS; i++) {
					if (0 == strcmp(optarg, counter_names[i])) {
						checktype = i;
						break;
					}
				}
				break;
			case 'i':
				add_filter("name", FILTER_EQ, optarg);
				break;
			case 'I':
				add_filter("name", FILTER_EQ | FILTER_EXCLUDE, optarg);
				break;
			case 'e':
				add_filter("name", FILTER_REGEX, optarg);
				break;
			case 'E':
				add_filter("name", FILTER_REGEX | FILTER_EXCLUDE, optarg);
				break;
			case 'l':
				list_disks = 1;
				break;
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
				exit(STATE_OK);
			case 'v':
				mp_verbosity++;
				break;
			case 'm':
				/**
				 * We are generous and accept both upper and lowercase
				 */
				for (i = 0; optarg[i]; i++) {
					optarg[i] = tolower(optarg[i]);
				}
				if (!strcmp(optarg, "b") || !strcmp(optarg, "kib") ||
				    !strcmp(optarg, "mib") || !strcmp(optarg, "gib") ||
				    !strcmp(optarg, "tib") || !strcmp(optarg, "pib") ||
				    !strcmp(optarg, "eib") || !strcmp(optarg, "zib") ||
				    !strcmp(optarg, "yib") || !strcmp(optarg, "%"))
				{
					thresholdunit = *optarg;
				} else {
					die(STATE_UNKNOWN, _("Wrong parameter for -m\n"));
				}
				break;
			case 'q':
				pre_time = strtol(optarg, NULL,0);
				debugtime = 1;
				break;
			case 'Q':
				cur_time = strtol(optarg, NULL,0);
				debugtime = 1;
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
 * Parse out the uom for warning and critical ranges
 * Calculate prefixedbytes to bytes and update thresholds to bytes
 * Returns 0 if OK
 */
static void update_threshold_range(range *r)
{
	unsigned int i, mul = 1;
	const char ssi_str[] = "bkmgtpezy";

	if (thresholdunit == '%')
		return;

	for (i = 0; i < sizeof(ssi_str); i++) {
		if (ssi_str[i] == thresholdunit)
			break;
		mul *= 1024;
	}
	if (!r->start_infinity)
		r->start = r->start * mul;
	if (!r->end_infinity)
		r->end = r->end * mul;
}

static int disk_compare(const void *a_, const void *b_)
{
	const struct disk_info *a = (struct disk_info *)a_;
	const struct disk_info *b = (struct disk_info *)b_;

	return a->Index - b->Index;
}

static int store_diskIOTable(
	netsnmp_variable_list *v,
	void *the_tree,
	void *discard
) {
	struct rbtree *t = (struct rbtree *)the_tree;
	struct disk_info *di, locator;

	if (v->name[11] == DISKIO_Index) {
		/* new disk, so create it and store it */
		di = disk_info_new();

		di->Index = *v->val.integer;
		rbtree_insert(t, di);
		return 0;
	}

	locator.Index = v->name[12];

	di = rbtree_find(t, (struct disk_info *)&locator);
	if (!di) {
		die(STATE_UNKNOWN,
			_("Unable to locate disk with index %d. "
			"Internal error or SNMP configuration error\n"), locator.Index);
	}

	di->have_vars |= (1 << v->name[11]);

	switch (v->name[11]) {
	 case DISKIO_Index:
		di->Index = *v->val.integer;
		break;
	 case DISKIO_Device:
		di->Device = strndup((char *)v->val.string, v->val_len);
		break;
	 case DISKIO_NRead:
		di->counter[COUNTER_nread] = *v->val.integer;
		break;
	 case DISKIO_NWritten:
		di->counter[COUNTER_nwritten] = *v->val.integer;
		break;
	 case DISKIO_Reads:
		di->counter[COUNTER_reads] = *v->val.integer;
		break;
	 case DISKIO_Writes:
		di->counter[COUNTER_writes] = *v->val.integer;
		break;
	 case DISKIO_LA1:
		di->LA1 = *v->val.integer;
		break;
	 case DISKIO_LA5:
		di->LA5 = *v->val.integer;
		break;
	 case DISKIO_LA15:
		di->LA15 = *v->val.integer;
		break;
	 default:
		break;
	}

	return 0;
}

static int get_diskIOTable(mp_snmp_context *ctx, struct rbtree *all_disks)
{
	if (mp_snmp_walk(
		ctx, DISKIOTABLE, NULL, store_diskIOTable, all_disks, NULL
		))
	{
		die(STATE_UNKNOWN, _("SNMP error when querying %s: %s\n"),
		    mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	return 0;
}

/*
 * This helper adds the data we would like to save to a string
 * so that we can write the string to the db file
 */
static int di_to_string(void *di_ptr, void *discard)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	char param_string[4096] = "";

	sprintf(param_string, "%d %s %d %d %d %d ",
			di->Index, di->Device, di->counter[COUNTER_nread],
			di->counter[COUNTER_nwritten], di->counter[COUNTER_reads],
			di->counter[COUNTER_writes]);
	strcat(save_string, param_string);
	return 0;
}

static int print_disk_entry(void *di_ptr, void *discard)
{
	struct disk_info *di = (struct disk_info *)di_ptr;

	printf("%s\n", di->Device);

	debugprint_disk_info("From disk entry", di_ptr, 3);
	return 0;
}

static void destroy_disk_filter(void *filter_ptr)
{
	struct disk_filter *df = (struct disk_filter *)filter_ptr;

	if (df == NULL) {
		return;
	}

	free(df->what_str);
	free(df->str);
	if (FILTER_HOW(df->how) == FILTER_REGEX)
		regfree(&df->preg);

	free(df);
}

static int match_used_bytes(void *di_ptr, void *result_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct di_result *r = (struct di_result *)result_ptr;
	double value = 0;
	int i, res = STATE_OK, tmp_res;

	if (load == checktype) {
		tmp_res = get_status((float)di->LA1, r->load1);
		res = max_state(tmp_res, res);
		tmp_res = get_status((float)di->LA5, r->load5);
		res = max_state(tmp_res, res);
		tmp_res = get_status((float)di->LA15, r->load15);
		res = max_state(tmp_res, res);

		if (STATE_CRITICAL == res) {
			rbtree_insert(r->critical, di);
		} else if (STATE_WARNING == res) {
			rbtree_insert(r->warning, di);
		}

	} else {
		for (i = 0; i<COUNTER_NELEMS - 1; i++) {
			if (i == checktype) {
				value = di->calc_counter[i];
				break;
			}
		}
		if (check_range(value, r->thresh->critical)) {
			rbtree_insert(r->critical, di);
		} else if (check_range(value, r->thresh->warning)) {
			rbtree_insert(r->warning, di);
		}
	}

	return 0;
}

static int di2output(void *di_ptr, void *num_left_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	int *num_left = (int *)num_left_ptr;
	int i;

	(*num_left)--;
	printf("%s: ", di->Device);
	for (i = 0; i<COUNTER_NELEMS; i++) {
		if (i == COUNTER_reads || i == COUNTER_writes) {
			printf("%s=%u/s ",
				counter_names[i], di->calc_counter[i]);
		}
		else {
			printf("%s=%s/s ",
				counter_names[i], humanize_bytes(di->calc_counter[i]));
		}
    }
    if (load == checktype) {
		printf("load1=%d%% load5=%d%% load15=%d%%%s",
			di->LA1, di->LA5, di->LA15, *num_left ? ", " : "");
	}
	return 0;
}

/* helper to quickly print perfdata ranges */
static const char *threshold_range2str(range *r, char *tmp_buf)
{
	static char str_ary[2][128]; /* 2 strings of 128 bytes is enough */
	static int slot = 0;
	double start, end;
	char *str;

	if (tmp_buf != NULL) {
		str = tmp_buf;
	} else {
		str = str_ary[slot];
		slot ^= 1; /* toggle between the two buffers */
	}

	start = r->start;
	end = r->end;

	if (r->start_infinity) {
		if (r->end_infinity) {
			return "~:";
		}
		snprintf(str, 128, "~:%.0f", end);
	} else if (r->end_infinity) {
		snprintf(str, 128, "%.0f:", start);
	} else {
		snprintf(str, 128, "%.0f:%.0f", start, end);
	}
	return str;
}

static int di2perfdata(void *di_ptr, void *dr_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct di_result *dr = (struct di_result *)dr_ptr;
	char tmp_buf[6][64];
	char *uom = "B";
	int i;

	/* Counter values */
	for (i = 0; i<COUNTER_NELEMS; i++) {
		if (i == COUNTER_reads || i == COUNTER_writes) {
			uom = "";
		}
		else {
			uom = "B";
		}
		printf("'%s_%s'=%d%s;%s;%s ",
			di->Device, counter_names[i], di->calc_counter[i], uom,
			threshold_range2str(dr->thresh->warning, NULL),
			threshold_range2str(dr->thresh->critical, NULL));
	}

	/* Load average */
	if (load == checktype) {
		printf("'%s_load1'=%d%%;%s;%s "
				"'%s_load5'=%d%%;%s;%s "
				"'%s_load15'=%d%%;%s;%s ",
				di->Device, di->LA1,
				threshold_range2str(dr->load1->warning, tmp_buf[0]),
				threshold_range2str(dr->load1->critical, tmp_buf[1]),
				di->Device, di->LA5,
				threshold_range2str(dr->load5->warning, tmp_buf[2]),
				threshold_range2str(dr->load5->critical, tmp_buf[3]),
				di->Device, di->LA15,
				threshold_range2str(dr->load15->warning, tmp_buf[4]),
				threshold_range2str(dr->load15->critical, tmp_buf[5]));
	}
	return 0;
}

/**
 * Loads the disk_info struct from previous check and inserts them into the
 * tree previous_tree for later comparison with the current check.
 */
static int load_state()
{
	struct disk_info *di;
	state_data *previous_state;
	char *buffer = NULL;
	char *token = NULL;
	int i;
	previous_state = np_state_read();
	if (previous_state == NULL) {
		return -1;
	}

	buffer = strdup(previous_state->data); /* get the data */
	if (0 == debugtime) { /* get the time if we are not in debug */
		pre_time = previous_state->time;
	}

	do {
		di = disk_info_new();

		if (NULL == token) {
			token = strtok(buffer, " ");
			if(!token) goto load_state_error;
			di->Index = strtoul(token, NULL, 10);
			i = 1;
		}

		for (i = i; i<COUNTER_NELEMS + 2; i++) { /* +2 due to index and descr */
			token = strtok(NULL, " ");
			if(!token) goto load_state_error;
			if (0 == i) {
				di->Index = strtoul(token, NULL, 10);
				continue;
			}
			if (1 == i) {
				disk_info_set_device(di,token);
				continue;
			}
			di->counter[i-2] = strtoul(token, NULL, 10);
		}

		rbtree_insert(previous_tree, di);
		i=0;
	} while (token);

	free(buffer);
	return 0;

load_state_error:
	mp_debug(3, "Problem parsing the previous state file\n");
	free(buffer);
	return 0;
}

static int save_state(struct rbtree *interesting)
{
	/**
	 * Traverse the interesting tree and save the information to
	 * the global string save_string and write it to the file
	 */
	rbtree_traverse(interesting, di_to_string, NULL, rbinorder);
	np_state_write_string(0, save_string);
	if (0 == debugtime) { /* save the current time if we are not in debug */
		time(&cur_time);
	}

	return 0;
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
			die(STATE_UNKNOWN,
				_("Too many threshold arguments\n"));
			return FALSE;
		}
		thrs[i] = token;
		token = strtok(NULL, ",");
		i++;
	}

	return TRUE;
}

#ifndef MP_TEST_PROGRAM
int main(int argc, char **argv)
#else
int main_as_in_test_program(int argc, char *argv[])
#endif /* MP_TEST_PROGRAM */
{
	struct rbtree *all_disks, *interesting;
	unsigned int num_left;
	static mp_snmp_context *ctx;
	struct di_result result;
	char *env_verbose;
	int state = STATE_OK;
	int initialize_db, counter, num_warning, num_critical, num_interesting;
	struct disk_info di_totals;
	size_t n_thresholds;
	char *warn_thrs[] = {"", "", ""};
	char *crit_thrs[] = {"", "", ""};

	all_disks       = rbtree_create(disk_compare);
	interesting     = rbtree_create(disk_compare);
	previous_tree   = rbtree_create(disk_compare);
	result.warning  = rbtree_create(disk_compare);
	result.critical = rbtree_create(disk_compare);
	filter_tree     = rbtree_create(filter_compare);

	if (!all_disks      || !interesting     || !previous_tree ||
	    !result.warning || !result.critical || !filter_tree)
	{
		die(STATE_UNKNOWN,
			_("Failed to allocate memory for disk read write\n"));
	}

	/* useful for debugging option parsing */
	if ((env_verbose = getenv("MP_VERBOSITY")))
		mp_verbosity = *env_verbose ? atoi(env_verbose) : 500;

	mp_snmp_init(program_name, 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);
	if (process_arguments(ctx, argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1)
		mp_snmp_debug_print_ctx(stdout, ctx);

	/**
	 * Parse tripple thresholds for load if needed,
	 * set standard monitoring-plugins thresholds and
	 * fix them according to the ssi elevation.
	 */
	if (load == checktype) {
		n_thresholds = ARRAY_SIZE(warn_thrs);
		parse_thresholds(warn_thrs, warn_str, n_thresholds);

		n_thresholds = ARRAY_SIZE(crit_thrs);
		parse_thresholds(crit_thrs, crit_str, n_thresholds);

		set_thresholds(&result.load1,  warn_thrs[0], crit_thrs[0]);
		set_thresholds(&result.load5,  warn_thrs[1], crit_thrs[1]);
		set_thresholds(&result.load15, warn_thrs[2], crit_thrs[2]);
	}

	set_thresholds(&result.thresh, warn_str, crit_str);
	update_threshold_range(result.thresh->warning);
	update_threshold_range(result.thresh->critical);

	get_diskIOTable(ctx, all_disks);
	mp_snmp_destroy_context(ctx);
	ctx = NULL;
	mp_snmp_deinit(program_name);
	num_left = rbtree_num_nodes(all_disks);

	mp_debug(3, "Found %d storage units\n", num_left);
	if (!num_left) {
		die(STATE_UNKNOWN, _("Failed to fetch data. "
			"Do we have permission to read diskIOTable?\n"));
	}

	/* filter out the unwanted ones */
	if (!discard_default_filters)
		add_filter("name", FILTER_REGEX | FILTER_EXCLUDE, "^ram|^loop");

	rbtree_traverse(all_disks, filter_disks, interesting, rbinorder);

	if (0 == rbtree_num_nodes(interesting))
		die(STATE_UNKNOWN, _("No storage units match your filters.\n"));

	/* Used to save the data between runs */
	np_init((char *)progname, argc, argv);

	/**
	 * Load a previous state of found, and save the current interesting rbtree
	 * with a timestamp to a file
	 */
	np_enable_state(NULL, 1);
	initialize_db = load_state();
	save_state(interesting);

	if (initialize_db == -1) {
		die(STATE_UNKNOWN, "UNKNOWN: No previous state, "
			"initializing database. Re-run the plugin\n");
	}

	/**
	 * Now do post-fetch calculations, calculate the time and then the counter
	 * differens per second between runs.
	 */
	dif_time = cur_time - pre_time;
	mp_debug(2, "previous time: %zu, current time: %zu, "
		"time difference: %zus\n", pre_time, cur_time, dif_time);
	rbtree_traverse(
		interesting, calc_disk_read_write, previous_tree, rbinorder);

	if (list_disks) {
		rbtree_traverse(interesting, print_disk_entry, NULL, rbinorder);
		return 0;
	}

	rbtree_traverse(interesting, match_used_bytes, &result, rbinorder);

	num_interesting = rbtree_num_nodes(interesting);
	num_warning = rbtree_num_nodes(result.warning);
	num_critical = rbtree_num_nodes(result.critical);
	if (num_critical) {
		state = STATE_CRITICAL;
	} else if (num_warning) {
		state = STATE_WARNING;
	}

	if (sum_all_disks && rbtree_num_nodes(interesting) > 1) {
		printf("%s: %d storage units selected. Sum ",
			state_text(state), rbtree_num_nodes(interesting));
		counter = 1;
		di2output(&di_totals, &counter);
		printf("\n|");
		di2perfdata(&di_totals, &result);
		putchar('\n');
	} else {
		/* now we construct the output */
		printf("%s: ", state_text(state));
		if (num_critical) {
			counter = num_critical;
			printf("%d/%d critical (", num_critical, num_interesting);
			rbtree_traverse(result.critical, di2output, &counter, rbinorder);
			printf(")");
		}
		if (num_warning) {
			counter = num_warning;
			printf("%d/%d warning (", num_warning, num_interesting);
			rbtree_traverse(result.warning, di2output, &counter, rbinorder);
			printf(")");
		}
		if (!num_warning && !num_critical) {
			counter = num_interesting;
			printf("%d/%d OK (", num_interesting, num_interesting);
			rbtree_traverse(interesting, di2output, &counter, rbinorder);
			printf(")");
		}

		printf("\n|");
		rbtree_traverse(interesting, di2perfdata, &result, rbinorder);
		putchar('\n');
	}

	/* Now make valgrind shut up. Helpful during development */
	rbtree_destroy(filter_tree,   (void (*)(void *))destroy_disk_filter);
	rbtree_destroy(all_disks,     (void (*)(void *))disk_info_destroy);
	rbtree_destroy(previous_tree, (void (*)(void *))disk_info_destroy);
	rbtree_destroy(interesting,     NULL);
	rbtree_destroy(result.critical, NULL);
	rbtree_destroy(result.warning,  NULL);
	if (result.thresh) {
		free(result.thresh->warning);
		free(result.thresh->critical);
		free(result.thresh);
	}

	return state;
}
