/**
 * Check disk/storage over snmp
 */
const char *progname = "check_by_snmp_disk";
const char *program_name = "check_by_snmp_disk"; /* for coreutils libs */

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

#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define HRSTORAGE_TABLE ".1.3.6.1.2.1.25.2.3.1" /* hrStorageEntry */
#define HRSTORAGE_SUBIDX_Index 1
#define HRSTORAGE_SUBIDX_Type 2					/* not used */
#define HRSTORAGE_SUBIDX_Descr 3
#define HRSTORAGE_SUBIDX_AllocationUnits 4
#define HRSTORAGE_SUBIDX_Size 5
#define HRSTORAGE_SUBIDX_Used 6
#define HRSTORAGE_SUBIDX_AllocationFailures 7

/*
 * HRSTORAGE_SUBIDX_Index not included, because we'll never
 * create a disk_info struct without getting it
 */
#define HRSTORAGE_ALL ( \
	(1 << HRSTORAGE_SUBIDX_Type) | \
	(1 << HRSTORAGE_SUBIDX_Descr) | \
	(1 << HRSTORAGE_SUBIDX_AllocationUnits) | \
	(1 << HRSTORAGE_SUBIDX_Size) | \
	(1 << HRSTORAGE_SUBIDX_Used))

/* Storage types, gleaned from HOST-RESOURCES-TYPES */
enum {
	STORAGE_TYPE_Other = 1,
	STORAGE_TYPE_Ram,
	STORAGE_TYPE_VirtualMemory,
	STORAGE_TYPE_FixedDisk,
	STORAGE_TYPE_RemovableDisk,
	STORAGE_TYPE_FloppyDisk,
	STORAGE_TYPE_CompactDisc,
	STORAGE_TYPE_RamDisk,
	STORAGE_TYPE_FlashMemory,
	STORAGE_TYPE_NetworkDisk,
};

#define STORAGE_MASK_DISK \
	(1 << STORAGE_TYPE_FixedDisk) | \
	(1 << STORAGE_TYPE_RemovableDisk) | \
	(1 << STORAGE_TYPE_NetworkDisk)
#define STORAGE_MASK_MEM \
	(1 << STORAGE_TYPE_Ram) | \
	(1 << STORAGE_TYPE_VirtualMemory)

static int disk_mask;
static int list_disks;
static char *warn_str = "", *crit_str = "";
static char thresholdunit = '%';
static struct rbtree *filter_tree;
static int discard_default_filters;
static int sum_all_disks;
static int include_filters, exclude_filters;
static char filter_charmap_magic[255];
#define num_filters (include_filters + exclude_filters)

struct di_result {
	char *uom;
	thresholds *thresh;
	struct rbtree *critical, *warning;
};

struct disk_info {
	unsigned int Index;
	unsigned int Type;
	char *Descr;
	unsigned int AllocationUnits;
	unsigned int Size;
	unsigned int Used;

	unsigned int have_vars;

	unsigned long long size_bytes;
	unsigned long long used_bytes;
	unsigned long long free_bytes;
	double pct_used;

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

/* parse a string with an optional SSI-y suffix to bytes */
static double parse_bytes(const char *str, int *err)
{
	double bytes;
	char s, *end, suffix[] = "kmgtpezy";
	unsigned int i;

	*err = 0;
	while (*str == '+')
		str++;

	/* not a number at start of string */
	if (*str < '0' || *str > '9')
		*err = 1;

	bytes = strtod(str, &end);
	if (!end || !*end)
		return bytes;

	s = tolower(*end);
	for (i = 0; i < sizeof(suffix); i++) {
		bytes *= 1024;
		if (s == suffix[i])
			return bytes;
	}

	/* invalid suffix */
	*err = 2;
	return 0;
}

#define prefixcasecmp(a, b) strncasecmp(a, b, strlen(a))
static int parse_disk_types(const char *orig_str)
{
	char *str, *comma;
	int error = 0, mask = 0;

	str = strdup(orig_str);
	do {
		comma = strchr(str, ',');
		if (comma)
			*comma = 0;

		if (!prefixcasecmp(str, "disk")) {
			mask |= STORAGE_MASK_DISK;
		} else if (!prefixcasecmp(str, "mem")) {
			mask |= STORAGE_MASK_MEM;
		} else if (!prefixcasecmp(str, "other")) {
			mask |= (1 << STORAGE_TYPE_Other);
		} else if (!prefixcasecmp(str, "ram")) {
			mask |= (1 << STORAGE_TYPE_Ram);
		} else if (!prefixcasecmp(str, "virtual") || !prefixcasecmp(str, "vmem")) {
			mask |= (1 << STORAGE_TYPE_VirtualMemory);
		} else if (!prefixcasecmp(str, "fixed")) {
			mask |= (1 << STORAGE_TYPE_FixedDisk);
		} else if (!prefixcasecmp(str, "removable")) {
			mask |= (1 << STORAGE_TYPE_RemovableDisk);
		} else if (!prefixcasecmp(str, "floppy")) {
			mask |= (1 << STORAGE_TYPE_FloppyDisk);
		} else if (!prefixcasecmp(str, "compact") || !strcasecmp(str, "cd") || !strcasecmp(str, "dvd")) {
			mask |= (1 << STORAGE_TYPE_CompactDisc);
		} else if (!prefixcasecmp(str, "ramdisk")) {
			mask |= (1 << STORAGE_TYPE_RamDisk);
		} else if (!prefixcasecmp(str, "flash")) {
			mask |= (1 << STORAGE_TYPE_FlashMemory);
		} else if (!prefixcasecmp(str, "net")) {
			mask |= (1 << STORAGE_TYPE_NetworkDisk);
		} else {
			mp_debug(1, "Unrecognized disktype: %s\n", str);
			error = 1;
		}
		if (comma) {
			*comma = ',';
			str = comma + 1;
		}
	} while (comma);

	if (error)
		return 0;

	return mask;
}

static int filter_what(const char *str)
{
	if (!strcasecmp("name", str))
		return FILTER_Name;
	if (!strcasecmp("size", str))
		return FILTER_Size;
	if (!strcasecmp("type", str))
		return FILTER_Type;
	if (!strcasecmp("blocksize", str))
		return FILTER_AllocationUnits;

	return -1;
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
static struct disk_filter *parse_filter(char *what_str, int flags, const char *orig_str)
{
	static unsigned int order = 0;
	struct disk_filter *f;
	int err;

	mp_debug(2, "Parsing '%s' filter from '%s' (flags: %d)\n", what_str, orig_str, flags);

	f = calloc(1, sizeof(*f));
	f->what = filter_what(what_str);
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
	 case FILTER_Type:
		/* disk type is handled separately */
		break;
	 case FILTER_Size:
	 case FILTER_AllocationUnits:
	 case FILTER_Used:
		f->value = parse_bytes(orig_str, &err);
		if (err) {
			die(STATE_UNKNOWN, _("Failed to parse %s to bytes\n"), orig_str);
		}
	 break;
	 case FILTER_Name:
		if (FILTER_HOW(flags) == FILTER_REGEX) {
			int ret = regcomp(&f->preg, f->str, REGEX_FLAGS);
			if (ret) {
				char errbuf[1024];
				regerror(ret, &f->preg, errbuf, sizeof(errbuf));
				die(STATE_UNKNOWN, _("Failed to compile regular expression: %s\n"), errbuf);
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
		die(STATE_UNKNOWN, _("Failed to parse %s filter from '%s'\n"), what_str, orig_str);
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
	         f->what_str, FILTER_HOW(f->how), f->str, di->Descr);
	switch (f->what) {
	 case FILTER_AllocationUnits:
		value = di->AllocationUnits;
		break;
	 case FILTER_Size:
		value = di->size_bytes;
		break;
	 case FILTER_Used:
	 	value = di->used_bytes;
		break;
	 case FILTER_Name:
		if (FILTER_HOW(f->how) == FILTER_REGEX) {
			int ret = regexec(&f->preg, di->Descr, 0, NULL, 0);
			if (!ret) {
				match = 1;
			}
		} else if (!strcmp(di->Descr, f->str)) {
			match = 1;
		}
		break;
	}

	if (value) {
		match = match_filter_value(f->how, value, f->value);
	}

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

static int filter_disks(void *di_ptr, void *to_tree)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct rbtree *target_tree = (struct rbtree *)to_tree;

	mp_debug(3, "Checking disk '%s' against filters\n", di->Descr ? di->Descr : "(noname; will be skipped)");
	if (!di->Descr) {
		die(STATE_UNKNOWN, _("Failed to read description for storage unit with index %d. Please check your SNMP configuration\n"), di->Index);
	}
	if (disk_mask && ((1 << di->Type) & disk_mask) == 0) {
		mp_debug(3, "   Wrong type\n");
		di->filter_out++;
	}
	if (!di->filter_out && (di->have_vars & HRSTORAGE_ALL) != HRSTORAGE_ALL) {
		mp_debug(3, "have_vars: %u; HRSTORAGE_ALL: %u; delta: %u\n", di->have_vars, HRSTORAGE_ALL, di->have_vars ^ HRSTORAGE_ALL);
		die(STATE_UNKNOWN, _("Failed to read data for storage unit %d (%s). Please check your SNMP configuration\n"),
		    di->Index, di->Descr ? di->Descr : "NULL");
	}

	if (!di->filter_out && filter_tree && rbtree_num_nodes(filter_tree)) {
		rbtree_traverse(filter_tree, filter_one_disk, di, rbinorder);
	}
	mp_debug(3, "   selected by %d/%d filters\n", di->filter_in, include_filters);
	mp_debug(3, "   discarded by %d/%d filterrs\n", di->filter_out, exclude_filters);
	if (!di->filter_out && (!include_filters || di->filter_in)) {
		mp_debug(3, "   +++ selected\n");
		rbtree_insert(target_tree, di);
	} else {
		mp_debug(3, "   --- discarded\n");
	}

	return 0;
}

static const char *storage_type_name(unsigned int type)
{
	/* static, because we want this in the .data segment */
	static const char *storage_types[] = {
		"Other",
		"Ram",
		"VirtualMemory",
		"FixedDisk",
		"RemovableDisk",
		"FloppyDisk",
		"CompactDisc",
		"RamDisk",
		"FlashMemory",
		"NetworkDisk",
	};

	/* snmp is 1-indexed. C is 0-indexed. Account for it */
	if (type > 0 && (type - 1) < (ARRAY_SIZE(storage_types)))
		return storage_types[type - 1];

	return "unknown";
}

/*
 * this is a tiny bit magic, but so long as it matches up with
 * storage_type_name, we really don't give a damn
 */
static int oid2storage_type(oid *o, unsigned int len)
{
	/* common parts for hrStorage{Other,Ram,...} */
	oid base_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1 };

	if (len < ARRAY_SIZE(base_oid)) {
		return -1;
	}

	if (memcmp(o, base_oid, sizeof(base_oid))) {
		return -1;
	}

	return o[ARRAY_SIZE(base_oid)];
}

void print_usage(void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s [--list] [-D] [-w <warn_range>] [-c <crit_range>]\n", progname);
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
	printf ("    %s\n", _("Unit of measurement for warning/critical range "
		"(default: %)"));
	printf ("    %s\n", _("%, b, kib, mib, gib, tib, pib, eib, zib or yib"));
	printf (" %s\n", "-l, --list");
	printf ("    %s\n", _("List all storage units selected by your filter\n"));
	printf (" %s\n", "-D, --discard-default-filters");
	printf ("    %s\n", _("Discard default filters"));
	printf (" %s\n", "-T, --types");
	printf ("    %s\n", _("Comma-separated list of storage types"));
	printf (" %s\n", "-e, --include-regex <regex>");
	printf ("    %s\n", _("Regular expression to match for inclusion"));
	printf (" %s\n", "-E, --exclude-regex <regex>");
	printf ("    %s\n", _("Regular expression to match for exclusion"));
	printf (" %s\n", "-i, --include-name <string>");
	printf ("    %s\n", _("Name of storage unit to include"));
	printf (" %s\n", "-I, --exclude-name <string>");
	printf ("    %s\n", _("Name of storage unit to exclude"));
	printf (" %s\n", "-s, --exclude-size <numcomparison>");
	printf ("    %s\n", _("Exclude units where total size does not match <numcomparison>"));
	printf (" %s\n", "-b, --exclude-blocks <numcomparison>");
	printf ("    %s\n", _("Exclude units where no of blocks does not match <numcomparison>"));
	printf (" %s\n", "-B, --exclude-blocksize <numcomparison>");
	printf ("    %s\n", _("Exclude units not where blocksize does not match <numcomparison>"));
	printf (" %s\n", "-u, --exclude-used <numcomparison>");
	printf ("    %s\n", _("Exclude units where used does not match <numcomparison>"));

	mp_snmp_argument_help();
	printf ("Notes on filters:\n");
	printf ("  * The type filter trumps all other filters\n");
	printf ("  * exclude filters always trump include filters\n");
	printf ("  * if no include filters are present, all units not excluded are included\n");
	printf ("  * --list prints all selected units\n");
	printf ("  * size/used/blocksize filters are always excluding\n");
	printf ("  * size filters take a comparison token. Use '--exclude-size -100MiB' to\n");
	printf ("      exclude units smaller than 100MiB\n");
	printf ("  * Default filters are --types disk --exclude-size -4k\n");
	printf ("  * <numcomparison> is of the form '+400' or '-400', meaning\n");
	printf ("      'greater than or equal to 400' and 'less than or equal to 400', respectively\n");
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
		{ "sum", no_argument, 0, 'S' },
		{ "discard-default-filters", no_argument, 0, 'D' },
		{ "list", no_argument, 0, 'l' },
		{ "include-name", required_argument, 0, 'i' },
		{ "exclude-name", required_argument, 0, 'I' },
		{ "include-regex", required_argument, 0, 'e' },
		{ "exclude-regex", required_argument, 0, 'E' },
		{ "exclude-size", required_argument, 0, 's' },
		{ "exclude-blocks", required_argument, 0, 'b' },
		{ "exclude-blocksize", required_argument, 0, 'B' },
		{ "exclude-used", required_argument, 0, 'u' },
		{ "types", required_argument, 0, 'T' },
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
			case 'S':
				sum_all_disks = 1;
				break;
			case 'D':
				discard_default_filters = 1;
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
			case 's':
				if (filter_charmap_magic[(int)*optarg] == *optarg) {
					add_filter("size", *optarg | FILTER_EXCLUDE, optarg + 1);
				} else {
					die(STATE_UNKNOWN, _("Option --exclude-size needs a comparison operator.\n"));
				}
				break;
			case 'b':
				if (filter_charmap_magic[(int)*optarg] == *optarg) {
					add_filter("blocks", *optarg | FILTER_EXCLUDE, optarg + 1);
				} else {
					add_filter("blocks", FILTER_EQ, optarg);
				}
				break;
			case 'B':
				if (filter_charmap_magic[(int)*optarg] == *optarg) {
					add_filter("blocksize", *optarg | FILTER_EXCLUDE, optarg + 1);
				} else {
					add_filter("blocksize", FILTER_EQ, optarg);
				}
				break;
			case 'u':
				if (filter_charmap_magic[(int)*optarg] == *optarg) {
					add_filter("used", *optarg | FILTER_EXCLUDE, optarg + 1);
				} else {
					die(STATE_UNKNOWN, _("Option --exclude-used needs a comparison operator.\n"));
				}
				break;
			case 'T':
				disk_mask = parse_disk_types(optarg);
				if (!disk_mask) {
					die(STATE_UNKNOWN, _("Invalid type filter: %s\n"), optarg);
				}
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

static int store_hrStorageTable(netsnmp_variable_list *v, void *the_tree, void *discard)
{
	struct rbtree *t = (struct rbtree *)the_tree;
	struct disk_info *di, locator;

	if (v->name[10] == HRSTORAGE_SUBIDX_Index) {
		/* new disk, so create it and store it */
		di = calloc(1, sizeof(*di));
		if (!di) {
			die(STATE_UNKNOWN, _("Failed to allocate memory for disk info data\n"));
		}
		di->Index = *v->val.integer;
		rbtree_insert(t, di);
		return 0;
	}

	locator.Index = v->name[11];

	di = rbtree_find(t, (struct disk_info *)&locator);
	if (!di) {
		die(STATE_UNKNOWN, _("Unable to locate disk with index %d. Internal error or SNMP configuration error\n"), locator.Index);
	}

	di->have_vars |= (1 << v->name[10]);

	switch (v->name[10]) {
	 case HRSTORAGE_SUBIDX_Type:
		di->Type = oid2storage_type(v->val.objid, v->val_len);
		break;
	 case HRSTORAGE_SUBIDX_Descr:
		di->Descr = strndup((char *)v->val.string, v->val_len);
		break;
	 case HRSTORAGE_SUBIDX_AllocationUnits:
		di->AllocationUnits = *v->val.integer;
		break;
	 case HRSTORAGE_SUBIDX_Size:
		di->Size = *v->val.integer;
		break;
	 case HRSTORAGE_SUBIDX_Used:
		di->Used = *v->val.integer;
		break;
	 case HRSTORAGE_SUBIDX_AllocationFailures:
		break;
	}

	return 0;
}

static int get_hrStorageTable(mp_snmp_context *ctx, struct rbtree *all_disks)
{
	if (mp_snmp_walk(ctx, HRSTORAGE_TABLE, NULL, store_hrStorageTable, all_disks, NULL))
	{
		die(STATE_UNKNOWN, _("SNMP error when querying %s: %s\n"),
		    mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	return 0;
}

/*
 * this helper just makes it a tad smoother to run filters
 * and print a disk_info struct
 */
static int calculate_disk_usage(void *di_ptr, void *discard)
{
	struct disk_info *di = (struct disk_info *)di_ptr;

	/* maintain precision */
	di->size_bytes = (unsigned long long)di->Size * di->AllocationUnits;
	di->used_bytes = (unsigned long long)di->Used * di->AllocationUnits;
	di->free_bytes = di->size_bytes - di->used_bytes;
	di->pct_used = 100.0 * (double)di->used_bytes / (double)di->size_bytes;
	return 0;
}

static int print_disk_entry(void *di_ptr, void *discard)
{
	struct disk_info *di = (struct disk_info *)di_ptr;

	printf("%-16s: %-14s %dK-blocks   %6.2f%% used of %s\n",
	       di->Descr, storage_type_name(di->Type),
	       di->AllocationUnits >> 10,
	       di->pct_used, humanize_bytes(di->size_bytes));
	return 0;
}

static void destroy_disk_info(void *di_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	free(di->Descr);
	free(di);
}

static void destroy_disk_filter(void *filter_ptr)
{
	struct disk_filter *df = (struct disk_filter *)filter_ptr;

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
	double value;

	value = '%' == thresholdunit ? di->pct_used : di->used_bytes;

	if (check_range(value, r->thresh->critical)) {
		rbtree_insert(r->critical, di);
	} else if (check_range(value, r->thresh->warning)) {
		rbtree_insert(r->warning, di);
	}

	return 0;
}

static int di2output(void *di_ptr, void *num_left_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	int *num_left = (int *)num_left_ptr;

	(*num_left)--;
	printf("%s: %.2f%% used of %s%s", di->Descr, di->pct_used,
	       humanize_bytes(di->size_bytes), *num_left ? ", " : "");
	return 0;
}

/* helper to quickly print perfdata ranges */
static const char *threshold_range2str(struct disk_info *di, range *r)
{
	static char str_ary[2][128]; /* 2 strings of 128 bytes is enough */
	static int slot = 0;
	double start, end;
	char *str;

	str = str_ary[slot];
	slot ^= 1; /* toggle between the two buffers */

	if ('%' == thresholdunit) {
		start = (double)di->size_bytes * r->start / 100.0;
		end = (double)di->size_bytes * r->end / 100.0;
	} else {
		start = r->start;
		end = r->end;
	}
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

static int di2perfdata(void *di_ptr, void *thresh_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	thresholds *thresh = (thresholds *)thresh_ptr;

	printf("'%s_used'=%lluB;%s;%s;0;%llu ",
	       di->Descr, di->used_bytes,
	       threshold_range2str(di, thresh->warning), threshold_range2str(di, thresh->critical),
	       di->size_bytes);

	return 0;
}

static int summarize_disks(void *di_ptr, void *tot_di_ptr)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	struct disk_info *tot = (struct disk_info *)tot_di_ptr;

	/* the "total" disk always uses 4k blocksize */
	tot->Used += di->Used * ((float)di->AllocationUnits / (float)tot->AllocationUnits);
	tot->Size += di->Size * ((float)di->AllocationUnits / (float)tot->AllocationUnits);
	return 0;
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
	int counter, num_warning, num_critical, num_interesting;
	struct disk_info di_totals;

	/* useful for debugging option parsing */
	if ((env_verbose = getenv("MP_VERBOSITY"))) {
		mp_verbosity = *env_verbose ? atoi(env_verbose) : 500;
	}

	all_disks = rbtree_create(disk_compare);
	interesting = rbtree_create(disk_compare);
	result.warning = rbtree_create(disk_compare);
	result.critical = rbtree_create(disk_compare);
	filter_tree = rbtree_create(filter_compare);
	if (!all_disks || !interesting || !result.warning || \
	    !result.critical || !filter_tree)
	{
		die(STATE_UNKNOWN, _("Failed to allocate memory for tracking disk storage\n"));
	}

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
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout, ctx);
	};

	/**
	 * Set standard monitoring-plugins thresholds
	 * and fix them according to the ssi elevation
	 */
	set_thresholds(&result.thresh, warn_str, crit_str);
	update_threshold_range(result.thresh->warning);
	update_threshold_range(result.thresh->critical);

	get_hrStorageTable(ctx, all_disks);
	mp_snmp_destroy_context(ctx);
	ctx = NULL;
	mp_snmp_deinit(program_name);
	num_left = rbtree_num_nodes(all_disks);

	mp_debug(3, "Found %d storage units\n", num_left);
	if (!num_left) {
		die(STATE_UNKNOWN, _("Failed to fetch data. Do we have permission to read hrStorageTable?\n"));
	}

	/* now do post-fetch calculations */
	rbtree_traverse(all_disks, calculate_disk_usage, NULL, rbinorder);

	/* filter out the unwanted ones */
	if (!discard_default_filters) {
		disk_mask = STORAGE_MASK_DISK;
		add_filter("size", FILTER_LT | FILTER_EXCLUDE, "4k");
		add_filter("name", FILTER_REGEX | FILTER_EXCLUDE, "^/run");
	}
	rbtree_traverse(all_disks, filter_disks, interesting, rbinorder);

	if (0 == rbtree_num_nodes(interesting)) {
		die(STATE_UNKNOWN, _("No storage units match your filters.\n"));
	}

	if (list_disks) {
		rbtree_traverse(interesting, print_disk_entry, NULL, rbinorder);
		return 0;
	}

	if (sum_all_disks && rbtree_num_nodes(interesting) > 1) {
		memset(&di_totals, 0, sizeof(di_totals));
		di_totals.Descr = "total";
		di_totals.AllocationUnits = 4096;
		rbtree_traverse(interesting, summarize_disks, &di_totals, rbinorder);
		calculate_disk_usage(&di_totals, NULL);
		match_used_bytes(&di_totals, &result);
	} else {
		rbtree_traverse(interesting, match_used_bytes, &result, rbinorder);
	}

	num_interesting = rbtree_num_nodes(interesting);
	num_warning = rbtree_num_nodes(result.warning);
	num_critical = rbtree_num_nodes(result.critical);
	if (num_critical)
		state = STATE_CRITICAL;
	else if (num_warning)
		state = STATE_WARNING;

	if (sum_all_disks && rbtree_num_nodes(interesting) > 1) {
		printf("%s: %d storage units selected. Sum ", state_text(state), rbtree_num_nodes(interesting));
		counter = 1;
		di2output(&di_totals, &counter);
		printf("\n|");
		di2perfdata(&di_totals, result.thresh);
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
		rbtree_traverse(interesting, di2perfdata, result.thresh, rbinorder);
		putchar('\n');
	}

	/* Now make valgrind shut up. Helpful during development */
	rbtree_destroy(filter_tree, destroy_disk_filter);
	rbtree_destroy(all_disks, destroy_disk_info);
	rbtree_destroy(interesting, NULL);
	rbtree_destroy(result.critical, NULL);
	rbtree_destroy(result.warning, NULL);
	if (result.thresh) {
		free(result.thresh->warning);
		free(result.thresh->critical);
		free(result.thresh);
	}

	return state;
}
