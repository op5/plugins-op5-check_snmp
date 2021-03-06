/**
 * Check system memory over snmp
 */
const char *progname = "check_by_snmp_memory";
const char *program_name = "check_by_snmp_memory"; /* Needed for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"

#define DEFAULT_TIME_OUT 15 /* only for help text atm */

/* UCD-SNMP-MIB for memory checks on linux systems */
#define MEMORY_TABLE "1.3.6.1.4.1.2021.4"
#define MEMORY_SUBIDX_MemIndex 1
#define MEMORY_SUBIDX_MemTotalSwap 3
#define MEMORY_SUBIDX_MemAvailSwap 4
#define MEMORY_SUBIDX_MemTotalReal 5
#define MEMORY_SUBIDX_MemAvailReal 6
#define MEMORY_SUBIDX_MemBuffer 14
#define MEMORY_SUBIDX_MemCached 15
#if 0
#define MEMORY_SUBIDX_MemTotalFree 11	/* Extra */
#define MEMORY_SUBIDX_MemMinimumSwap 12	/* Extra */
#define MEMORY_SUBIDX_MemShared 13		/* Extra */
#define MEMORY_SUBIDX_MemErrorName 2	/* Usually not in use or bogus */
#define MEMORY_SUBIDX_MemTotalSwapTXT 7
#define MEMORY_SUBIDX_MemAvailSwapTXT 8
#define MEMORY_SUBIDX_MemTotalRealTXT 9
#define MEMORY_SUBIDX_MemAvailRealTXT 10
#define MEMORY_SUBIDX_MemSwapError 100
#define MEMORY_SUBIDX_MemSwapErrorMsg 101
#endif

enum o_monitortype_t {
	MONITOR_TYPE__RAM_USED,
	MONITOR_TYPE__SWAP_USED
};

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);
int tolower(int);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
char *thresholdunit = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__RAM_USED; /* default */

struct mem_info {
	unsigned int Index;
	unsigned int TotalSwap;
	unsigned int AvailSwap;
	unsigned int TotalReal;
	unsigned int AvailReal;
	unsigned int Buffer;
	unsigned int Cached;
	unsigned int UsedReal; /* calculated */
	unsigned int UsedSwap; /* calculated */
	int index_found;
	int totalswap_found;
	int availswap_found;
	int totalreal_found;
	int availreal_found;
	int buffer_found;
	int cached_found;
};
/**
 * Calculated memory info values used for checking and printing output
 * with perfdata
 */
struct cmi {
	double bytes_used;
	double bytes_buffer;
	double bytes_cached;
	double bytes_free;
	double percent_used;
	double total_size;
};

static int mem_callback(netsnmp_variable_list *v, void *mc_ptr, void *discard)
{
	struct mem_info *mc = (struct mem_info *)mc_ptr;

	switch (v->name[8]) {
		case MEMORY_SUBIDX_MemIndex:
			mc->Index = *v->val.integer;
			mc->index_found = 1;
			break;
		case MEMORY_SUBIDX_MemTotalSwap:
			mc->TotalSwap = *v->val.integer;
			mc->totalswap_found = 1;
			break;
		case MEMORY_SUBIDX_MemAvailSwap:
			mc->AvailSwap = *v->val.integer;
			mc->availswap_found = 1;
			break;
		case MEMORY_SUBIDX_MemTotalReal:
			mc->TotalReal = *v->val.integer;
			mc->totalreal_found = 1;
			break;
		case MEMORY_SUBIDX_MemAvailReal:
			mc->AvailReal = *v->val.integer;
			mc->availreal_found = 1;
			break;
		case MEMORY_SUBIDX_MemBuffer:
			mc->Buffer = *v->val.integer;
			mc->buffer_found = 1;
			break;
		case MEMORY_SUBIDX_MemCached:
			mc->Cached = *v->val.integer;
			mc->cached_found = 1;
			break;
	}
	return EXIT_SUCCESS;
}

struct mem_info *check_mem_ret(mp_snmp_context *ss, int statemask)
{
	struct mem_info *mi = malloc(sizeof(struct mem_info));
	memset(mi, 0, sizeof(struct mem_info));

	if (0 != mp_snmp_walk(ss, MEMORY_TABLE, NULL, mem_callback, mi, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		    mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}
	if (0 == mi->availreal_found || 0 == mi->availswap_found ||
		0 == mi->buffer_found || 0 == mi->cached_found || 0 == mi->index_found ||
		0 == mi->totalreal_found || 0 == mi->totalswap_found)
	{
		die(STATE_UNKNOWN, "UNKNOWN: Could not fetch the values at %s. "
			"Please check your config file for SNMP and make sure you have access\n", MEMORY_TABLE);
	}

	/* Calculate the used values */
	mi->UsedReal = mi->TotalReal - mi->AvailReal - mi->Buffer - mi->Cached;
	mi->UsedSwap = mi->TotalSwap - mi->AvailSwap;

	mp_debug(3,
		"Memory: %ukb total, %ukb used, %ukb free, %ukb buffers, %ukb cached\n"
		"Swap: \t%ukb total, %ukb used, %ukb free\n",
		mi->TotalReal, mi->UsedReal, mi->AvailReal, mi->Buffer, mi->Cached,
		mi->TotalSwap, mi->UsedSwap, mi->AvailSwap);

	return mi;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s [-T <type>] [-m <unit_range>]\n", progname);
	printf ("   [-w <warn_range>] [-c <crit_range>]\n");
	mp_snmp_argument_usage();
}

void print_help (void)
{
	print_revision (progname, NP_VERSION);
	printf ("%s\n", _("Check status of remote machines and obtain system "
		"information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf (" %s\n", "-T, --type=STRING");
	printf ("    %s\n", _("Type of check (default: ram_used)"));
	printf ("    %s\n", _("ram_used or swap_used"));
	printf (" %s\n", "-m, --uom");
	printf ("    %s\n", _("Unit of measurement for warning/critical range "
		"(default: %)"));
	printf ("    %s\n", _("%, b, kib, mib, gib, tib, pib, eib, zib or yib"));

	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
int process_arguments (int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"type", required_argument, 0, 'T'},
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
				if (0==strcmp(optarg, "ram_used")) {
					o_monitortype = MONITOR_TYPE__RAM_USED;
				} else if (0==strcmp(optarg, "swap_used")) {
					o_monitortype = MONITOR_TYPE__SWAP_USED;
				} else {
					die(STATE_UNKNOWN, _("Wrong parameter for -T\n"));
				}
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
int update_thr(thresholds **thresh, double total_size)
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

int main(int argc, char **argv)
{
	const int KIBPREFIX = 1024; /* Returned value from SNMP is in KiB */
	int result = STATE_UNKNOWN;
	static thresholds *thresh;
	struct cmi *cmiptr = (struct cmi *) malloc(sizeof(struct cmi));
	struct mem_info *ptr; /* Allocated in called function */
	const char *uom = "B";

	mp_snmp_init(program_name, 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);
	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the snmp_context
	 */
	if (0 != mp_snmp_finalize_auth(ctx)) {
		die(STATE_UNKNOWN, _("Failed to finalize SNMP authentication\n"));
	}

	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	}

	/**
	 *  Set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	ptr = check_mem_ret(ctx, ~0); /* get net-snmp memory data */
	mp_snmp_deinit(program_name); /* deinit */
	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__RAM_USED:
			cmiptr->bytes_used = (double)ptr->UsedReal * KIBPREFIX;
			cmiptr->total_size = (double)ptr->TotalReal * KIBPREFIX;
			cmiptr->percent_used = (double)(cmiptr->bytes_used / cmiptr->total_size) * 100;
			cmiptr->bytes_free = (double)cmiptr->total_size - cmiptr->bytes_used;
			cmiptr->bytes_buffer = (double)ptr->Buffer * KIBPREFIX;
			cmiptr->bytes_cached = (double)ptr->Cached * KIBPREFIX;

			if (update_thr(&thresh, cmiptr->total_size) != 0) {
				die(STATE_UNKNOWN, _("Failed to convert ranges to bytes\n"));
			}

			result = get_status (cmiptr->bytes_used, thresh);
			printf("%s: Used RAM: %.2lf%% (%s) of total %s |%s %s %s %s",
				state_text(result),
				cmiptr->percent_used,
				(char*)humanize_bytes(cmiptr->bytes_used),
				(char*)humanize_bytes(cmiptr->total_size),
				perfdata ("RAM Used", cmiptr->bytes_used, uom,
					thresh->warning?TRUE:FALSE, thresh->warning?thresh->warning->end:FALSE,
					thresh->critical?TRUE:FALSE, thresh->critical?thresh->critical->end:FALSE,
					TRUE, 0, TRUE, cmiptr->total_size),
				perfdata ("RAM Buffered", cmiptr->bytes_buffer, uom,
					FALSE, FALSE,
					FALSE, FALSE,
					TRUE, 0, TRUE, cmiptr->total_size),
				perfdata ("RAM Cached", cmiptr->bytes_cached, uom,
					FALSE, FALSE,
					FALSE, FALSE,
					TRUE, 0, TRUE, cmiptr->total_size),
				perfdata ("RAM Free", cmiptr->bytes_free, uom,
					FALSE, FALSE,
					FALSE, FALSE,
					TRUE, 0, TRUE, cmiptr->total_size));
			break;
		case MONITOR_TYPE__SWAP_USED:
			cmiptr->bytes_used = (double)ptr->UsedSwap * KIBPREFIX;
			cmiptr->total_size = (double)ptr->TotalSwap * KIBPREFIX;
			cmiptr->percent_used = (double)(cmiptr->bytes_used / cmiptr->total_size) * 100;
			cmiptr->bytes_free = (double)cmiptr->total_size - cmiptr->bytes_used;

			if (update_thr(&thresh, cmiptr->total_size) != 0) {
				die(STATE_UNKNOWN, _("Failed to convert ranges to bytes\n"));
			}

			result = get_status (cmiptr->bytes_used, thresh);
			printf("%s: Used Swap: %.2lf%% (%s) of total %s |%s %s",
				state_text(result),
				cmiptr->percent_used,
				(char*)humanize_bytes(cmiptr->bytes_used),
				(char*)humanize_bytes(cmiptr->total_size),
				perfdata ("Swap Used", cmiptr->bytes_used, uom,
					thresh->warning?TRUE:FALSE, thresh->warning?thresh->warning->end:FALSE,
					thresh->critical?TRUE:FALSE, thresh->critical?thresh->critical->end:FALSE,
					TRUE, 0, TRUE, cmiptr->total_size),
				perfdata ("Swap Free", cmiptr->bytes_free, uom,
					FALSE, FALSE,
					FALSE, FALSE,
					TRUE, 0, TRUE, cmiptr->total_size));
			break;
		default:
			usage4 (_("Could not parse arguments for -T"));
			break;
	}
	printf("\n");

	free(ctx);
	free(ptr);
	free(cmiptr);

	return result;
}
