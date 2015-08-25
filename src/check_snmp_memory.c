/**
 * Check system memory over snmp
 */
const char *progname = "check_snmp_memory";
const char *program_name = "check_snmp_memory"; /* Required for coreutils libs */
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"

#define DEFAULT_TIME_OUT 15			/* only for help text atm */

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
	MONITOR_TYPE__RAM_FREE,
	MONITOR_TYPE__SWAP_USED,
	MONITOR_TYPE__BUFFER_KB,
	MONITOR_TYPE__BUFFER_MB,
	MONITOR_TYPE__BUFFER_GB,
	MONITOR_TYPE__CACHED_KB,
	MONITOR_TYPE__CACHED_MB,
	MONITOR_TYPE__CACHED_GB
};

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__RAM_USED; /* default */
int o_perfdata = 1; /* perfdata on per default */

struct mem_info {
	int Index;
	int TotalSwap;
	int AvailSwap;
	int TotalReal;
	int AvailReal;
	int Buffer;
	int Cached;
	int UsedReal; /* calculated from TotalReal-AvailReal */
	int UsedSwap; /* calculated from TotalSwap-AvailSwap */
};
/**
 * Calculated memory info values used for checking and printing output
 * with and without perfdata
 */
struct cmi {
	int ram_used;
	int ram_free;
	int swap_used;
	int buffer_mb;
	int buffer_gb;
	int cached_mb;
	int cached_gb;
};

static int mem_callback(netsnmp_variable_list *v, void *mc_ptr, void *discard)
{
	struct mem_info *mc = (struct mem_info *)mc_ptr;

	switch (v->name[8]) {
		case MEMORY_SUBIDX_MemIndex:
			mc->Index=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemTotalSwap:
			mc->TotalSwap=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemAvailSwap:
			mc->AvailSwap=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemTotalReal:
			mc->TotalReal=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemAvailReal:
			mc->AvailReal=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemBuffer:
			mc->Buffer=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemCached:
			mc->Cached=*v->val.integer;
			break;
	}
	return EXIT_SUCCESS;
}

struct mem_info *check_mem_ret(mp_snmp_context *ss, int statemask)
{
	struct mem_info *mi = (struct mem_info *) malloc(sizeof(struct mem_info));
	memset(mi, 0, sizeof(struct mem_info));
	if (0 != mp_snmp_walk(ss, MEMORY_TABLE, NULL, mem_callback, mi, NULL)) {
		die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
		    mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
	}

	/* calculate the used values */
	mi->UsedReal = mi->TotalReal-mi->AvailReal;
	mi->UsedSwap = mi->TotalSwap-mi->AvailSwap;

	mp_debug(3,"Memory: %dkb total, %dkb used, %dkb free, %dkb buffers\nSwap: \t%dkb total, %dkb used, %dkb free, %dkb cached\n",
				mi->TotalReal, mi->UsedReal, mi->AvailReal, mi->Buffer,
				mi->TotalSwap, mi->UsedSwap, mi->AvailSwap, mi->Cached);

	return mi;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community>\n",progname);
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
	printf ("	%s\n", _("ram_used (default)"));
	printf ("	%s\n", _("ram_free"));
	printf ("	%s\n", _("swap_used"));
	printf ("	%s\n", _("buffer_in_kb"));
	printf ("	%s\n", _("buffer_in_mb"));
	printf ("	%s\n", _("buffer_in_gb"));
	printf ("	%s\n", _("cached_in_kb"));
	printf ("	%s\n", _("cached_in_mb"));
	printf ("	%s\n", _("cached_in_gb"));
	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
int process_arguments (int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;
	mp_snmp_init(program_name, 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"usage", no_argument, 0, 'u'},
		{"perfdata", no_argument, 0, 'f'},
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
			case 'u':
				print_usage();
				exit(STATE_OK);
				break;
			case 'f':
				o_perfdata = 0;
				break;
			case 'T':
				if (0==strcmp(optarg, "ram_used")) {
					o_monitortype = MONITOR_TYPE__RAM_USED;
				} else if (0==strcmp(optarg, "ram_free")) {
					o_monitortype = MONITOR_TYPE__RAM_FREE;
				} else if (0==strcmp(optarg, "swap_used")) {
					o_monitortype = MONITOR_TYPE__SWAP_USED;
				} else if (0==strcmp(optarg, "buffer_in_kb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_KB;
				} else if (0==strcmp(optarg, "buffer_in_mb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_MB;
				} else if (0==strcmp(optarg, "buffer_in_gb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_GB;
				} else if (0==strcmp(optarg, "cached_in_kb")) {
					o_monitortype = MONITOR_TYPE__CACHED_KB;
				} else if (0==strcmp(optarg, "cached_in_mb")) {
					o_monitortype = MONITOR_TYPE__CACHED_MB;
				} else if (0==strcmp(optarg, "cached_in_gb")) {
					o_monitortype = MONITOR_TYPE__CACHED_GB;
				}
			break;
		}
	}

	free(optary);
	return TRUE;
}

int main(int argc, char **argv)
{
	const int MBPREFIX = 1024;
	static thresholds *thresh;
	struct mem_info *ptr;
	struct cmi *cmiptr = (struct cmi *) malloc(sizeof(struct cmi));
	char *uom = "%"; /* used with perfdata */
	int result = STATE_UNKNOWN;
	
	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);
	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/**
	 *  Set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	};

	ptr = check_mem_ret(ctx, ~0); /* get net-snmp memory data */
	mp_snmp_deinit(program_name); /* deinit */
	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__RAM_USED:
			cmiptr->ram_used = (ptr->TotalReal-ptr->AvailReal)*100/ptr->TotalReal;
			result = get_status(cmiptr->ram_used, thresh);
			printf("%s: %d%% Ram used ", state_text(result), cmiptr->ram_used);
			if (o_perfdata == 1) {
				printf("|'Ram used'=%d%s;%s;%s",
						cmiptr->ram_used, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__RAM_FREE:
			cmiptr->ram_free = ptr->AvailReal*100/ptr->TotalReal;
			result = get_status(cmiptr->ram_free, thresh);
			printf("%s: %d%% Ram free ", state_text(result), cmiptr->ram_free);
			if (o_perfdata == 1) {
				printf("|'Ram free'=%d%s;%s;%s",
						cmiptr->ram_free, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__SWAP_USED:
			cmiptr->swap_used = (ptr->TotalSwap-ptr->AvailSwap)*100/ptr->TotalSwap;
			result = get_status(cmiptr->swap_used, thresh);
			printf("%s: %d%% Swap used ", state_text(result), cmiptr->swap_used);
			if (o_perfdata == 1) {
				printf("|'Swap used'=%d%s;%s;%s",
						cmiptr->swap_used, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_KB:
			uom = "KB";
			result = get_status (ptr->Buffer, thresh);
			printf("%s: %d%s Memory Buffer ", state_text(result), ptr->Buffer, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s",
						ptr->Buffer, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_MB:
			uom = "MB";
			cmiptr->buffer_mb = ptr->Buffer/MBPREFIX;
			result = get_status (cmiptr->buffer_mb, thresh);
			printf("%s: %d%s Memory Buffer ", state_text(result), cmiptr->buffer_mb, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s",
						cmiptr->buffer_mb, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_GB:
			uom = "GB";
			cmiptr->buffer_gb = ptr->Buffer/(MBPREFIX*MBPREFIX);
			result = get_status (cmiptr->buffer_gb, thresh);
			printf("%s: %d%s Memory Buffer ", state_text(result), cmiptr->buffer_gb, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s",
						cmiptr->buffer_gb, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__CACHED_KB:
			uom = "KB";
			result = get_status (ptr->Cached, thresh);
			printf("%s: %d%s Memory Cached ", state_text(result), ptr->Cached, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Cached'=%d%s;%s;%s",
						ptr->Cached, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__CACHED_MB:
			uom = "MB";
			cmiptr->cached_mb = ptr->Cached/MBPREFIX;
			result = get_status (cmiptr->cached_mb, thresh);
			printf("%s: %d%s Memory Cached ", state_text(result), cmiptr->cached_mb, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Cached'=%d%s;%s;%s",
						cmiptr->cached_mb, uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__CACHED_GB:
			uom = "GB";
			cmiptr->cached_gb = ptr->Cached/(MBPREFIX*MBPREFIX);
			result = get_status(cmiptr->cached_gb, thresh);
			printf("%s: %d%s Memory Cached ", state_text(result), cmiptr->cached_gb, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Cached'=%d%s;%s;%s",
						cmiptr->cached_gb, uom, warn_str, crit_str);
			}
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
