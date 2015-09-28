/**
 * Check disk/storage over snmp
 */
const char *progname = "check_snmp_disk";
const char *program_name = "check_snmp_disk"; /* for coreutils libs */

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <stdio.h>					/* to calculate iowait */
#include <time.h>					/* to calculate iowait */

#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define HRSTORAGE_TABLE "1.3.6.1.2.1.25.2.3.1" /* hrStorageEntry */
#define HRSTORAGE_SUBIDX_Index 1
#define HRSTORAGE_SUBIDX_Type 2					/* not used */
#define HRSTORAGE_SUBIDX_Descr 3
#define HRSTORAGE_SUBIDX_AllocationUnits 4
#define HRSTORAGE_SUBIDX_Size 5
#define HRSTORAGE_SUBIDX_Used 6
#define HRSTORAGE_SUBIDX_AllocationFailures 7

#define DISKIO_TABLE ".1.3.6.1.4.1.2021.13.15.1.1" /* diskIOTable */
#define DISKIO_SUBIDX_Index 1
#define DISKIO_SUBIDX_Device 2
#define DISKIO_SUBIDX_NRead 3		/* not used */
#define DISKIO_SUBIDX_NWritten 4	/* not used */
#define DISKIO_SUBIDX_Reads 5		/* not used */
#define DISKIO_SUBIDX_Writes 6		/* not used */
#define DISKIO_SUBIDX_LA1 9
#define DISKIO_SUBIDX_LA5 10
#define DISKIO_SUBIDX_LA15 11
#define DISKIO_SUBIDX_ReadX 12		/* not used */
#define DISKIO_SUBIDX_WrittenX 13	/* not used */

enum o_monitortype_t {
	MONITOR_TYPE__STORAGE,
	MONITOR_TYPE__IO
};

enum o_monitor_presentationtype_t {
	MONITOR_PRESTYPE__IO_1,
	MONITOR_PRESTYPE__IO_5,
	MONITOR_PRESTYPE__IO_15
};

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);
int tolower(int);

mp_snmp_context *ctx;
char *warn_str = "", *crit_str = "";
enum o_monitortype_t o_monitortype = MONITOR_TYPE__STORAGE;
int get_index = 0;
char *o_disk = NULL;
char *thresholdunit = "";
enum o_monitor_presentationtype_t o_type;

struct disk_info {
	int Index;
	int Type;
	char *Descr;
	int AllocationUnits;
	int Size;
	int Used;
	int AllocationFailures;	/* counter */
	struct {
		int Index;
		char *Descr;
		int La1;
		int La5;
		int La15;
	} IO;
};

/**
 * Helper functions to let the user use the name of the disk rather than the
 * index and functions to print the available storages to check.
 */
static int get_disk_index_from_desc(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[10]) {
		case HRSTORAGE_SUBIDX_Descr:
			if (0 == strcmp(o_disk, strndup((char*)v->val.string, v->val_len))) {
				get_index = v->name[11];
			}
			break;
		default:
			mp_debug(3,"Unknown disk description.\n");
			break;
	}
	return EXIT_SUCCESS;
}

static int get_io_index_from_desc(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[11]) {
		case DISKIO_SUBIDX_Device:
			if (0 == strcmp(o_disk, strndup((char*)v->val.string, v->val_len))) {
				get_index = v->name[12];
			}
			break;
		default:
			mp_debug(3,"Unknown io description.\n");
			break;
	}
	return EXIT_SUCCESS;
}

static int disk_index_and_description_output(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[10]) {
		case HRSTORAGE_SUBIDX_Descr:
			printf("%ld\t", v->name[11]);
			printf("%s\n", strndup((char*)v->val.string, v->val_len));
			break;
		default:
			mp_debug(3,"Unknown disk description.\n");
			break;
	}
	return EXIT_SUCCESS;
}

static int io_index_and_description_output(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[11]) {
		case DISKIO_SUBIDX_Device:
			printf("%ld\t", v->name[12]);
			printf("%s\n", strndup((char*)v->val.string, v->val_len));
			break;
		default:
			mp_debug(3,"Unknown io description.\n");
			break;
	}
	return EXIT_SUCCESS;
}

/**
 * Helper functions to get all the relevant data over SNMP and store it
 * in a structure which stores the data for further use in the plugin.
 */
static int disk_callback(netsnmp_variable_list *v, void *dc_ptr, void *discard)
{
	struct disk_info *dc = (struct disk_info *)dc_ptr;

	switch (v->name[10]) {
		case HRSTORAGE_SUBIDX_Index:
			mp_debug(3,"Index: %ld\n",*v->val.integer);
			if(v->name[11] == get_index)
				dc->Index=*v->val.integer;
			break;
		case HRSTORAGE_SUBIDX_Type:
			dc->Type=*v->val.integer;
			mp_debug(3,"Type: %ld\n",*v->val.integer);
			break;
		case HRSTORAGE_SUBIDX_Descr:
			mp_debug(3,"Description: %s\n",strndup((char*)v->val.string, v->val_len));
			if(v->name[11] == get_index)
				dc->Descr=strndup((char*)v->val.string, v->val_len);
			break;
		case HRSTORAGE_SUBIDX_AllocationUnits:
			mp_debug(3,"AllocationUnits: %ld\n",*v->val.integer);
			if(v->name[11] == get_index)
				dc->AllocationUnits=*v->val.integer;
			break;
		case HRSTORAGE_SUBIDX_Size:
			mp_debug(3,"Size: %ld\n",*v->val.integer);
			if(v->name[11] == get_index)
				dc->Size=*v->val.integer;
			break;
		case HRSTORAGE_SUBIDX_Used:
			mp_debug(3,"Used: %ld\n",*v->val.integer);
			if(v->name[11] == get_index)
				dc->Used=*v->val.integer;
			break;
		default:
			mp_debug(3,"Unknown disk_callback value.\n");
			break;
	}
	return EXIT_SUCCESS;
}

static int io_callback(netsnmp_variable_list *v, void *dc_ptr, void *discard)
{
	struct disk_info *dc = (struct disk_info *)dc_ptr;

	switch (v->name[11]) {
		case DISKIO_SUBIDX_Index:
			mp_debug(3,"Index: %ld\n",*v->val.integer);
			if(v->name[12] == get_index)
				dc->IO.Index=*v->val.integer;
			break;
		case DISKIO_SUBIDX_Device:
			mp_debug(3,"Description: %s\n", strndup((char*)v->val.string, v->val_len));
			if(v->name[12] == get_index)
				dc->IO.Descr=strndup((char*)v->val.string, v->val_len);
			break;
		case DISKIO_SUBIDX_NRead:
			mp_debug(3,"NRead: %ld\n", *v->val.integer);
			break;
		case DISKIO_SUBIDX_NWritten:
			mp_debug(3,"NWritten: %ld\n", *v->val.integer);
			break;
		case DISKIO_SUBIDX_Reads:
			mp_debug(3,"Reads: %ld\n", *v->val.integer);
			break;
		case DISKIO_SUBIDX_Writes:
			mp_debug(3,"Writes: %ld\n", *v->val.integer);
			break;
		case DISKIO_SUBIDX_LA1:
			mp_debug(3,"IO Load-1: %ld\n",*v->val.integer);
			if(v->name[12] == get_index)
				dc->IO.La1=*v->val.integer;
			break;
		case DISKIO_SUBIDX_LA5:
			mp_debug(3,"IO Load-5: %ld\n",*v->val.integer);
			if(v->name[12] == get_index)
				dc->IO.La5=*v->val.integer;
			break;
		case DISKIO_SUBIDX_LA15:
			mp_debug(3,"IO Load-15: %ld\n",*v->val.integer);
			if(v->name[12] == get_index)
				dc->IO.La15=*v->val.integer;
			break;
		case DISKIO_SUBIDX_ReadX:
			mp_debug(3,"ReadX: %ld\n", *v->val.integer);
			break;
		case DISKIO_SUBIDX_WrittenX:
			mp_debug(3,"WrittenX: %ld\n", *v->val.integer);
			break;
		default:
			mp_debug(3,"Unknown io_callback value.\n");
			break;
	}
	return EXIT_SUCCESS;
}

/**
 * Use helper functions to get all the relevant data over SNMP and store it
 * in a structure which stores the data for further use in the plugin. Since
 * we like the user to use the name of the disk rather than the index we
 * handle it here.
 */
struct disk_info *check_disk_ret(mp_snmp_context *ss, int statemask)
{
	struct disk_info *cd = (struct disk_info *) malloc(sizeof(struct disk_info));
	memset(cd, 0, sizeof(struct disk_info));
	
	/* Lists the index and description for all available disk storages */
	if (get_index == 0 && o_disk == NULL) {
		printf("### Fetched storage data over NET-SNMP ###\n");
		printf("Index:\tDescription:\n");
		if (0 != mp_snmp_walk(ss, "1.3.6.1.2.1.25.2.3.1.3", NULL, disk_index_and_description_output, cd, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		}
		exit(STATE_OK);
	}
	else {
		/* get the index from description */
		if (0 != mp_snmp_walk(ss, "1.3.6.1.2.1.25.2.3.1.3", NULL, get_disk_index_from_desc, cd, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		}
		
		/* get and store the relevant data for the disk */
		mp_debug(3,"\nFetched data over NET-SNMP:\n");
		if (0 != mp_snmp_walk(ss, HRSTORAGE_TABLE, NULL, disk_callback, cd, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		}
		mp_debug(3,"\nStored values:\n");
		mp_debug(3,"Index: %d, Description: %s, AllocationUnits %d, Size %d, Used %d\n",
		cd->Index, cd->Descr, cd->AllocationUnits, cd->Size, cd->Used);
	}

	return cd;
}
struct disk_info *check_disk_io_ret(mp_snmp_context *ss, int statemask)
{
	struct disk_info *cdi = (struct disk_info *) malloc(sizeof(struct disk_info));
	memset(cdi, 0, sizeof(struct disk_info));
	
	/* Lists the index and description for all available disk IO */
	if (get_index == 0 && o_disk == NULL) {
		printf("### Fetched IO data over NET-SNMP ###\n");
		printf("Index:\tDescription:\n");
		if (0 != mp_snmp_walk(ss,".1.3.6.1.4.1.2021.13.15.1.1.2" , NULL, io_index_and_description_output, cdi, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		}
		exit(STATE_OK);
	}
	else {
		/* get the index from description */
		if (0 != mp_snmp_walk(ss,".1.3.6.1.4.1.2021.13.15.1.1.2" , NULL, get_io_index_from_desc, cdi, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		}

		/* get and store the relevant data for the disk */
		mp_debug(3,"\nFetched data over NET-SNMP:\n");
		if (0 != mp_snmp_walk(ss, DISKIO_TABLE, NULL, io_callback, cdi, NULL)) {
			die(STATE_UNKNOWN, "UNKNOWN: SNMP error when querying %s: %s\n",
				mp_snmp_get_peername(ctx), mp_snmp_get_errstr(ctx));
		};
		mp_debug(3,"\nStored values:\n");
		mp_debug(3,"Index: %d, Description: %s, La1 %d, La5 %d, La15 %d\n",
		cdi->IO.Index, cdi->IO.Descr, cdi->IO.La1, cdi->IO.La5, cdi->IO.La15);
	}

	return cdi;
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

void print_help(void)
{
	print_revision(progname, NP_VERSION);
	printf ("%s\n", _("Check status of remote machines and obtain system "
		"information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	printf (" %s\n", "-T, --type=STRING");
	printf ("    %s\n", _("storage_list - List available storages to check"));
	printf ("    %s\n", _("storage_used - Storage used (default)"));
	printf ("    %s\n", _("io_list - List available disks to check I/O"));
	printf ("    %s\n", _("io_1 - I/O load average 1 min"));
	printf ("    %s\n", _("io_5 - I/O load average 5 min"));
	printf ("    %s\n", _("io_15 - I/O load average 15 min"));
	printf (" %s\n", "-i, --indexname=STRING");
	printf ("    %s\n", _("STRING - Name of disk to check"));
	printf (" %s\n", "-m, --uom");
	printf ("    %s\n", _("Unit of measurement for warning/critical range "
		"(default: %)"));
	printf ("    %s\n", _("%, b, kb, mb, gb, tb, pb, eb, zb or yb"));

	mp_snmp_argument_help();
	printf ( UT_WARN_CRIT_RANGE);
}

/* process command-line arguments */
int process_arguments(int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"diskname", required_argument, 0, 'i'},
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
				exit(STATE_OK);
			case 'v':
				mp_verbosity++;
				break;
			case 'i':
				o_disk = optarg;
				break;
			case 'T':
				if (0==strcmp(optarg, "storage_list")) {
					o_monitortype = MONITOR_TYPE__STORAGE;
				} else if (0==strcmp(optarg, "storage_used")) {
					o_monitortype = MONITOR_TYPE__STORAGE;
				} else if (0==strcmp(optarg, "io_list")) {
					o_monitortype = MONITOR_TYPE__IO;
				} else if (0==strcmp(optarg, "io_1")) {
					o_monitortype = MONITOR_TYPE__IO;
					o_type = MONITOR_PRESTYPE__IO_1;
				} else if (0==strcmp(optarg, "io_5")) {
					o_monitortype = MONITOR_TYPE__IO;
					o_type = MONITOR_PRESTYPE__IO_5;
				} else if (0==strcmp(optarg, "io_15")) {
					o_monitortype = MONITOR_TYPE__IO;
					o_type = MONITOR_PRESTYPE__IO_15;
				} else {
					die(STATE_UNKNOWN, _("Wrong parameter for -T.\n"));
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
				} else if (0 == strcmp(optarg, "kb")) {
					thresholdunit = "k";
				} else if (0 == strcmp(optarg, "mb")) {
					thresholdunit = "m";
				} else if (0 == strcmp(optarg, "gb")) {
					thresholdunit = "g";
				} else if (0 == strcmp(optarg, "tb")) {
					thresholdunit = "t";
				} else if (0 == strcmp(optarg, "pb")) {
					thresholdunit = "p";
				} else if (0 == strcmp(optarg, "eb")) {
					thresholdunit = "e";
				} else if (0 == strcmp(optarg, "zb")) {
					thresholdunit = "z";
				} else if (0 == strcmp(optarg, "yb")) {
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

static const char *humanize_bytes(double bytes)
{
	static char buf[32][16];
	static int buf_i = 0;
	char *p;
	const char *suffix[] = { "byte", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB" };
	unsigned int suff_i = 0;

	while (suff_i < ARRAY_SIZE(suffix) && bytes > 1024) {
		bytes /= 1024;
		suff_i++;
	}
	p = buf[buf_i++];
	sprintf(p, "%.2lf%s", bytes, suffix[suff_i]);
	return p;
}

/**
 * Used to transform the warning and critical values from prefixedbytes to bytes
 */
double prefixedbytes_to_bytes(double bytes, const char *uom)
{
	const char *prefix[] = { "b", "k", "m", "g", "t", "p", "e", "z", "y" };
	unsigned int pref_i = 0;
	while (pref_i < ARRAY_SIZE(prefix)) {
		if (0==strcmp(uom, prefix[pref_i])) {
			break;
		} else {
			bytes = bytes * 1024;
			pref_i++;
		}
	}
	return bytes;
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
	int result = STATE_UNKNOWN;
	static thresholds *thresh;
	struct disk_info *ptr = NULL;
	char *uom = "%"; /* used with perfdata */
	double bytes, total_size, percent_used, bytes_free;

	mp_snmp_init(program_name, 0);

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);
	if (process_arguments(argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/**
	 * Finalize authentication of the snmp context and print possible debug info
	 * about the mp_snmp_context
	 */
	mp_snmp_finalize_auth(ctx);
	if (mp_verbosity >= 1) {
		mp_snmp_debug_print_ctx(stdout,ctx);
	};

	/**
	 *  Set standard monitoring-plugins thresholds
	 */
	set_thresholds(&thresh, warn_str, crit_str);

	/* get, calculate and set result status */
	switch (o_monitortype) {
		case MONITOR_TYPE__STORAGE:
			ptr = check_disk_ret(ctx, ~0);	/* get net-snmp disk data */
			mp_snmp_deinit(program_name);	/* deinit */
			if (ptr->Descr == NULL) {
				die(STATE_UNKNOWN, _("Invalid input string for -i "
					"(Use -T storage_list for a list of valid strings).\n"));
			}

			percent_used = (double)ptr->Used/(double)ptr->Size*100;
			bytes = (double)ptr->Used*ptr->AllocationUnits;
			total_size = (double)ptr->Size*ptr->AllocationUnits;
			bytes_free = total_size - bytes;

			if (update_thr(&thresh, total_size) != 0) {
				die(STATE_UNKNOWN,
					_("Failed to convert ranges to bytes\n"));
			}

			result = get_status (bytes, thresh);
			char *used_msg;
			char *free_msg;
			xasprintf (&used_msg, _("Used %s"), ptr->Descr);
			xasprintf (&free_msg, _("Free %s"), ptr->Descr);
			printf("%s: Used space on '%s': %.2lf%% (%s) of total %s |%s %s",
				state_text(result),
				ptr->Descr,
				percent_used,
				(char*)humanize_bytes(bytes),
				(char*)humanize_bytes(total_size),
				fperfdata (used_msg, bytes, "B",
					thresh->warning?TRUE:FALSE, thresh->warning?thresh->warning->end:FALSE,
					thresh->critical?TRUE:FALSE, thresh->critical?thresh->critical->end:FALSE,
					TRUE, 0, TRUE, total_size),
				fperfdata (free_msg, bytes_free, "B",
					FALSE, FALSE,
					FALSE, FALSE,
					TRUE, 0, TRUE, total_size));

			break;
		case MONITOR_TYPE__IO:
			ptr = check_disk_io_ret(ctx, ~0);	/* get net-snmp io data */
			mp_snmp_deinit(program_name);		/* deinit */
			if (ptr->IO.Descr == NULL) {
				die(STATE_UNKNOWN, _("Invalid input string for -i "
					"(Use -T io_list for a list of valid strings)\n"));
			}

			if (o_type == MONITOR_PRESTYPE__IO_1) {
				result = get_status(ptr->IO.La1, thresh);
				printf("%s: %d%s IO Load-1 ", state_text(result), ptr->IO.La1, uom);
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La1,
						uom, warn_str, crit_str);
			}
			else if (o_type == MONITOR_PRESTYPE__IO_5) {
				result = get_status(ptr->IO.La5, thresh);
				printf("%s: %d%s IO Load-5 ", state_text(result), ptr->IO.La5, uom);
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La5,
						uom, warn_str, crit_str);
			}
			else if (o_type == MONITOR_PRESTYPE__IO_15) {
				result = get_status(ptr->IO.La15, thresh);
				printf("%s: %d%s IO Load-15 ", state_text(result), ptr->IO.La15, uom);
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La15,
						uom, warn_str, crit_str);
			}
			else
				die(STATE_UNKNOWN, _("Could not handle -T option\n"));
			break;
		default:
			die(STATE_UNKNOWN, _("UNKNOWN: Not a valid monitor type\n"));
	}

	printf("\n");

	free(ctx);
	free(ptr);

	return result;
}
