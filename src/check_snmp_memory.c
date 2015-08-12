/**
 * Check system memory over snmp
 * Add a big description
 */
const char *progname = "check_snmp_memory";
const char *program_name = "check_snmp_memory"; /* Required for coreutils libs */
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";
 
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"

#define DEFAULT_COMMUNITY "public" 	/* only for help text atm */
#define DEFAULT_PORT "161"			/* only for help text atm */
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
	MONITOR_TYPE__CACHED_KB
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

static void print_output_header(int result) {
	/* output result state */
	if (result == STATE_OK)
			printf("OK: ");
	if (result == STATE_WARNING)
			printf("WARNING: ");
	if (result == STATE_CRITICAL)
			printf("CRITICAL: ");
	if (result == STATE_UNKNOWN)
			printf("UNKNOWN: ");
}

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
	mp_snmp_walk(ss, MEMORY_TABLE, NULL, mem_callback, mi, NULL);
	
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
	/* printf (UT_EXTRA_OPTS); */
	printf (" %s\n", "-T, --type=STRING");
	printf ("	%s\n", _("ram_used (default)"));
	printf ("	%s\n", _("ram_free"));
	printf ("	%s\n", _("swap_used"));
	printf ("	%s\n", _("buffer_in_kb"));
	printf ("	%s\n", _("buffer_in_mb"));
	printf ("	%s\n", _("buffer_in_gb"));
	printf ("	%s\n", _("cached_in_kb"));
	printf (" %s\n", "-H, --hostname=STRING");
	printf ("    %s\n", _("IP address to the SNMP server"));
	printf (" %s\n", "-C, --community=STRING");
	printf ("	%s\n", _("Community string for SNMP communication"));
	printf (" %s\n", "-P, --protocol=[1|2c|3]");
	printf ("    %s\n", _("SNMP protocol version"));
	printf (" %s\n", "-L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]");
	printf ("    %s\n", _("SNMPv3 securityLevel"));
	printf (" %s\n", "-a, --authproto=[MD5|SHA]");
	printf ("    %s\n", _("SNMPv3 auth proto"));
	printf (" %s\n", "-x, --privproto=[DES|AES]");
	printf ("    %s\n", _("SNMPv3 priv proto (default DES)"));
	printf (" %s\n", "-U, --secname=USERNAME");
	printf ("    %s\n", _("SNMPv3 username"));
	printf (" %s\n", "-A, --authpassword=PASSWORD");
	printf ("    %s\n", _("SNMPv3 authentication password"));
	printf (" %s\n", "-X, --privpasswd=PASSWORD");
	printf ("    %s\n", _("SNMPv3 privacy password"));
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
	mp_snmp_finalize_auth(ctx);

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
	optary[i++] = '+';
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
				}else if (0==strcmp(optarg, "buffer_in_kb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_KB;
				} else if (0==strcmp(optarg, "buffer_in_mb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_MB;
				} else if (0==strcmp(optarg, "buffer_in_gb")) {
					o_monitortype = MONITOR_TYPE__BUFFER_GB;
				} else if (0==strcmp(optarg, "cached_in_kb")) {
					o_monitortype = MONITOR_TYPE__CACHED_KB;
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
	
	ptr = check_mem_ret(ctx, ~0); /* get net-snmp memory data */
	mp_snmp_deinit(program_name); /* deinit */

	/* check and output results */
	switch (o_monitortype) {
		case MONITOR_TYPE__RAM_USED:
			result = get_status ((double)((ptr->TotalReal-ptr->AvailReal)*100/ptr->TotalReal), thresh);
			print_output_header(result);
			printf("%d%% Ram used ", (ptr->TotalReal-ptr->AvailReal)*100/ptr->TotalReal);
			if (o_perfdata == 1) {
				printf("|'Ram used'=%d%s;%s;%s", 
					(ptr->TotalReal-ptr->AvailReal)*100/ptr->TotalReal,
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__RAM_FREE:
			result = get_status ((double)ptr->AvailReal*100/ptr->TotalReal, thresh);
			print_output_header(result);
			printf("%d%% Ram free ", ptr->AvailReal*100/ptr->TotalReal);
			if (o_perfdata == 1) {
				printf("|'Ram free'=%d%s;%s;%s",
					ptr->AvailReal*100/ptr->TotalReal,
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__SWAP_USED:
			result = get_status ((double)((ptr->TotalSwap-ptr->AvailSwap)*100/ptr->TotalSwap), thresh);
			print_output_header(result);
			printf("%d%% Swap used ", (ptr->TotalSwap-ptr->AvailSwap)*100/ptr->TotalSwap);
			if (o_perfdata == 1) {
				printf("|'Swap used'=%d%s;%s;%s",
					(ptr->TotalSwap-ptr->AvailSwap)*100/ptr->TotalSwap,
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_KB:
			result = get_status (ptr->Buffer, thresh);
			print_output_header(result);
			uom = "KB";
			printf("%d%s Memory Buffer ", ptr->Buffer, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s", ptr->Buffer,
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_MB:
			result = get_status (ptr->Buffer/MBPREFIX, thresh);
			print_output_header(result);
			uom = "MB";
			printf("%d%s Memory Buffer ", ptr->Buffer/MBPREFIX, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s", ptr->Buffer/MBPREFIX,
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__BUFFER_GB:
			result = get_status (ptr->Buffer/(MBPREFIX*MBPREFIX), thresh);
			print_output_header(result);
			uom = "GB";
			printf("%d%s Memory Buffer ", ptr->Buffer/(MBPREFIX*MBPREFIX), uom);
			if (o_perfdata == 1) {
				printf("|'Memory Buffer'=%d%s;%s;%s", ptr->Buffer/(MBPREFIX*MBPREFIX),
					uom, warn_str, crit_str);
			}
			break;
		case MONITOR_TYPE__CACHED_KB:
			result = get_status (ptr->Cached, thresh);
			print_output_header(result);
			uom = "KB";
			printf("%d%s Memory Cached ", ptr->Cached, uom);
			if (o_perfdata == 1) {
				printf("|'Memory Cached'=%d%s;%s;%s", ptr->Cached,
					uom, warn_str, crit_str);
			}
			break;
		default:
			usage4 (_("Could not parse arguments for -T"));
			break;
	}
	printf("\n");
	
	free(ctx);
	free(ptr);

	return result;
}
