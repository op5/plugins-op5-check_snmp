/**
 * Check disk/storage over snmp
 */
const char *progname = "check_snmp_disk";
const char *program_name = "check_snmp_disk"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <naemon/naemon.h>

#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define HRSTORAGE_TABLE ".1.3.6.1.2.1.25.2.3.1" /* hrStorageEntry */
#define HRSTORAGE_SUBIDX_Index 1
#define HRSTORAGE_SUBIDX_Type 2					/* not used */
#define HRSTORAGE_SUBIDX_Descr 3
#define HRSTORAGE_SUBIDX_AllocationUnits 4
#define HRSTORAGE_SUBIDX_Size 5
#define HRSTORAGE_SUBIDX_Used 6
#define HRSTORAGE_SUBIDX_AllocationFailures 7

/* Storage types, gleaned from HOST-RESOURCES-TYPES */
enum {
	STORAGE_TYPE_Other,
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

static int list_disks = 1;
static char *warn_str = "", *crit_str = "";
static char *o_disk = NULL;
static char *thresholdunit = "";

struct disk_info {
	int Index;
	int Type;
	char *Descr;
	int AllocationUnits;
	int Size;
	int Used;
	struct disk_info *next;
};

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
	printf ("%s -H <ip_address> -C <snmp_community> -i <name of disk> "
		"[-T <type>]\n",progname);
	printf ("[-m<unit_range>] [-w<warn_range>] "
			"[-c<crit_range>] [-t <timeout>]\n");
	printf ("([-P snmp version] [-L seclevel] [-U secname]\n");
	printf ("[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])\n");
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
	printf (" %s\n", "-m, --uom");
	printf ("    %s\n", _("Unit of measurement for warning/critical range "
		"(default: %)"));
	printf ("    %s\n", _("%, b, kib, mib, gib, tib, pib, eib, zib or yib"));

	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
static int process_arguments(mp_snmp_context *ctx, int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"diskname", required_argument, 0, 'i'},
		{"uom", required_argument, 0, 'm'},
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
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;
		if (!mp_snmp_handle_argument(ctx, c, optarg))
			continue;

		switch (c) {
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
			case 'i':
				o_disk = optarg;
				break;
			case 'm':
				/**
				 * We are generous and accept both upper and lowercase
				 */
				for (i = 0; optarg[i]; i++) {
					optarg[i] = tolower(optarg[i]);
				}
				if (0 == strcmp(optarg, "b")) {
					thresholdunit = "b";
				} else if (0 == strcmp(optarg, "kib")) {
					thresholdunit = "k";
				} else if (0 == strcmp(optarg, "mib")) {
					thresholdunit = "m";
				} else if (0 == strcmp(optarg, "gib")) {
					thresholdunit = "g";
				} else if (0 == strcmp(optarg, "tib")) {
					thresholdunit = "t";
				} else if (0 == strcmp(optarg, "pib")) {
					thresholdunit = "p";
				} else if (0 == strcmp(optarg, "eib")) {
					thresholdunit = "e";
				} else if (0 == strcmp(optarg, "zib")) {
					thresholdunit = "z";
				} else if (0 == strcmp(optarg, "yib")) {
					thresholdunit = "y";
				} else if (0 == strcmp(optarg, "%")) {
					thresholdunit = "%";
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
static int update_thr(thresholds **thresh, double total_size)
{
	char *uom_str;
	const char *prefix_str = "bkmgtpezy";

	if ((uom_str = strpbrk(thresholdunit, prefix_str)) != NULL) {
		(*thresh)->warning->start =
			prefixedbytes_to_bytes((*thresh)->warning->start, uom_str);
		(*thresh)->warning->end =
			prefixedbytes_to_bytes((*thresh)->warning->end, uom_str);

	} else {
		(*thresh)->warning->start =
			((*thresh)->warning->start / 100) * total_size;
		(*thresh)->warning->end =
			((*thresh)->warning->end / 100) * total_size;
	}

	if ((uom_str = strpbrk(thresholdunit, prefix_str)) != NULL) {
		(*thresh)->critical->start =
			prefixedbytes_to_bytes((*thresh)->critical->start, uom_str);
		(*thresh)->critical->end =
			prefixedbytes_to_bytes((*thresh)->critical->end, uom_str);
	} else {
		(*thresh)->critical->start =
			((*thresh)->critical->start / 100) * total_size;
		(*thresh)->critical->end =
			((*thresh)->critical->end / 100) * total_size;
	}
	return 0;
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

static int print_disk_entry(void *di_ptr, void *discard)
{
	struct disk_info *di = (struct disk_info *)di_ptr;
	unsigned long long size, used;
	double pct_used;

	/* maintain precision */
	size = (unsigned long long)di->Size * (unsigned long long)di->AllocationUnits;
	used = (unsigned long long)di->Used * (unsigned long long)di->AllocationUnits;
	pct_used = ((double)used / (double)size) * 100.0;
	printf("%-16s: %-14s %dK-blocks   %6.2f%% used of %s\n",
	       di->Descr, storage_type_name(di->Type),
	       di->AllocationUnits >> 10,
	       pct_used, humanize_bytes(size));
	return 0;
}

#ifndef MP_TEST_PROGRAM
int main(int argc, char **argv)
{
	static thresholds *thresh;
	struct rbtree *all_disks = NULL;
	unsigned int num_left;
	static mp_snmp_context *ctx;

	all_disks = rbtree_create(disk_compare);
	if (!all_disks) {
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

	get_hrStorageTable(ctx, all_disks);
	mp_snmp_destroy_context(ctx);
	ctx = NULL;
	num_left = rbtree_num_nodes(all_disks);

	mp_debug(3, "Found %d storage units\n", num_left);
	if (!num_left) {
		die(STATE_UNKNOWN, _("Failed to fetch data. Do we have permission to read hrStorageTable?\n"));
	}

	/**
	 *  Set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	if (1 || list_disks) /* XXX: Remove "1 ||" when finished */
		rbtree_traverse(all_disks, print_disk_entry, NULL, rbinorder);

	/*
	 * TODO:
	 * apply filters (all_disks -> interesting_disks)
	 * match thresholds against filtered units
	 *   (interesting -> critical, interesting -> warning)
	 * construct output string based on non-ok filtered units
	 * construct perfdata string based on "interesting_disks"
	 */
	printf("OK: All disks within thresholds.\n");
	return 0;
}
#endif /* MP_TEST_PROGRAM */
