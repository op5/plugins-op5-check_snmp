/**
 * Check os specific aspects over snmp
 * Add a big description
 */
const char *progname = "check_snmp_os";
const char *program_name = "check_snmp_os"; /* for coreutils libs */
const char *copyright = "2015";
const char *email = "devel@monitoring-plugins.org";

#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
#include <stdio.h>					/* to calculate iowait */
#include <time.h>					/* to calculate iowait */

#define DEFAULT_COMMUNITY "public" 	/* only used for help text */
#define DEFAULT_PORT "161"			/* only used for help text */
#define DEFAULT_TIME_OUT 15			/* only used for help text */

#define TCPCONNECTION_TABLE ".1.3.6.1.2.1.6" /* hrStorageEntry */
#define TCPCONNECTION_SUBIDX_LocalPort 3
#define HRSTORAGE_SUBIDX_Type 2					/* not used */
#define HRSTORAGE_SUBIDX_Descr 3
#define HRSTORAGE_SUBIDX_AllocationUnits 4
#define HRSTORAGE_SUBIDX_Size 5
#define HRSTORAGE_SUBIDX_Used 6
#define HRSTORAGE_SUBIDX_AllocationFailures 7

#define DISKIO_TABLE ".1.3.6.1.4.1.2021.13.15.1.1" /* diskIOTable */
#define DISKIO_SUBIDX_Index 1
#define DISKIO_SUBIDX_Device 2
#define DISKIO_SUBIDX_NRead 3					/* not used */
#define DISKIO_SUBIDX_NWritten 4				/* not used */
#define DISKIO_SUBIDX_Reads 5					/* not used */
#define DISKIO_SUBIDX_Writes 6					/* not used */
#define DISKIO_SUBIDX_LA1 9
#define DISKIO_SUBIDX_LA5 10
#define DISKIO_SUBIDX_LA15 11
#define DISKIO_SUBIDX_ReadX 12					/* not used */
#define DISKIO_SUBIDX_WrittenX 13				/* not used */

int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);

mp_snmp_context *ctx;
char *warn_str = NULL, *crit_str = NULL;
int o_monitortype = 1;
int o_perfdata = 0;
int o_get_index = 0;
int o_type = 1;

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

static int
disk_index_output(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[10]) {
		case HRSTORAGE_SUBIDX_Descr:
			printf("%ld\t", v->name[11]);
			printf("%s\n", strndup(v->val.string, v->val_len));
			break;
		default:
			mp_debug(3,"Unknown disk_index_output value.\n");
			break;
	}
	return 0;
}
static int
io_index_output(netsnmp_variable_list *v, void *ptr, void *discard)
{
	switch (v->name[11]) {
		case DISKIO_SUBIDX_Device:
			printf("%ld\t", v->name[12]);
			printf("%s\n", strndup(v->val.string, v->val_len));
			break;
		default:
			mp_debug(3,"Unknown io_index_output value.\n");
			break;
	}
	return 0;
}

static int
disk_callback(netsnmp_variable_list *v, void *dc_ptr, void *discard)
{
	struct disk_info *dc = (struct disk_info *)dc_ptr;

	switch (v->name[10]) {
		case HRSTORAGE_SUBIDX_Index:
			mp_debug(3,"Index: %ld\n",*v->val.integer);
			if(v->name[11] == o_get_index)
				dc->Index=*v->val.integer;
			break;
		case HRSTORAGE_SUBIDX_Type:
			dc->Type=*v->val.integer;
			mp_debug(3,"Type: %ld\n",*v->val.integer);
			break;
		case HRSTORAGE_SUBIDX_Descr:
			mp_debug(3,"Description: %s\n",strndup(v->val.string, v->val_len));		
			if(v->name[11] == o_get_index)
				dc->Descr=strndup(v->val.string, v->val_len);			
			break;
		case HRSTORAGE_SUBIDX_AllocationUnits:
			mp_debug(3,"AllocationUnits: %ld\n",*v->val.integer);
			if(v->name[11] == o_get_index)
				dc->AllocationUnits=*v->val.integer;			
			break;
		case HRSTORAGE_SUBIDX_Size:
			mp_debug(3,"Size: %ld\n",*v->val.integer);
			if(v->name[11] == o_get_index)
				dc->Size=*v->val.integer;			
			break;
		case HRSTORAGE_SUBIDX_Used:
			mp_debug(3,"Used: %ld\n",*v->val.integer);	
			if(v->name[11] == o_get_index)
				dc->Used=*v->val.integer;
			break;
		default:
			mp_debug(3,"Unknown disk_callback value.\n");
			break;
	}
	return 0;
}
static int
io_callback(netsnmp_variable_list *v, void *dc_ptr, void *discard)
{
	struct disk_info *dc = (struct disk_info *)dc_ptr;

	switch (v->name[11]) {
		case DISKIO_SUBIDX_Index:
			mp_debug(3,"Index: %ld\n",*v->val.integer);
			if(v->name[12] == o_get_index)
				dc->IO.Index=*v->val.integer;
			break;
		case DISKIO_SUBIDX_Device:
			mp_debug(3,"Description: %s\n", strndup(v->val.string, v->val_len));
			if(v->name[12] == o_get_index)
				dc->IO.Descr=strndup(v->val.string, v->val_len);			
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
			if(v->name[12] == o_get_index)
				dc->IO.La1=*v->val.integer;
			break;
		case DISKIO_SUBIDX_LA5:
			mp_debug(3,"IO Load-5: %ld\n",*v->val.integer);
			if(v->name[12] == o_get_index)
				dc->IO.La5=*v->val.integer;			
			break;
		case DISKIO_SUBIDX_LA15:
			mp_debug(3,"IO Load-15: %ld\n",*v->val.integer);
			if(v->name[12] == o_get_index)
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
	return 0;
}

struct disk_info *check_disk_ret(mp_snmp_context *ss, int statemask)
{
	struct disk_info *cd = (struct disk_info *) malloc(sizeof(struct disk_info));
	memset(cd, 0, sizeof(struct disk_info));
	
	/* Lists the index and all available disks/io to check */
	if(o_get_index == 0 && o_monitortype == 1) {
		printf("### Fetched storage data over NET-SNMP ###\n");
		printf("Index:\tDescription:\n");
		mp_snmp_walk(ss, "1.3.6.1.2.1.25.2.3.1.3", NULL, disk_index_output, cd, NULL);
		exit(STATE_OK);
	}
	else {
		mp_debug(3,"\nFetched data over NET-SNMP:\n");
		mp_snmp_walk(ss, HRSTORAGE_TABLE, NULL, disk_callback, cd, NULL);
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
	
	/* Lists the index and all available disks/io to check */
	if (o_get_index == 0) {
		printf("### Fetched IO data over NET-SNMP ###\n");
		printf("Index:\tDescription:\n");
		mp_snmp_walk(ss,".1.3.6.1.4.1.2021.13.15.1.1.2" , NULL, io_index_output, cdi, NULL);
		exit(STATE_OK);
	}
	else {
		mp_debug(3,"\nFetched data over NET-SNMP:\n");
		mp_snmp_walk(ss, DISKIO_TABLE, NULL, io_callback, cdi, NULL);
		mp_debug(3,"\nStored values:\n");
		mp_debug(3,"Index: %d, Description: %s, La1 %d, La5 %d, La15 %d\n",
		cdi->IO.Index, cdi->IO.Descr, cdi->IO.La1, cdi->IO.La5, cdi->IO.La15);
	}

	return cdi;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community> -i <index of disk>\n",progname);
	printf ("[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [1|2|3|4]] \n");
	printf ("([-P snmp version] [-N context] [-L seclevel] [-U secname]\n");
	printf ("[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd])\n");
}

void print_help (void)
{
	print_revision (progname, NP_VERSION);
	printf (COPYRIGHT, copyright, email);
	printf ("%s\n", _("Check status of remote machines and obtain system information via SNMP"));
	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_VERBOSE);
	printf (UT_PLUG_TIMEOUT, DEFAULT_TIME_OUT);
	/* printf (UT_EXTRA_OPTS); */
	printf (" %s\n", "-H, --hostname=STRING");
	printf ("    %s\n", _("IP address to the SNMP server"));
	printf (" %s\n", "-C, --community=STRING");
	printf ("	%s\n", _("Community string for SNMP communication"));
	printf (" %s\n", "-m, --monitordisktype=[1|2|3|4]");
	printf ("	%s\n", _("1 - Storage (default)"));
	printf ("	%s\n", _("2 - I/O"));
	printf (" %s\n", "-i, --indexofdisk=<int>");
	printf ("	%s\n", _("0 - Storage index list (default)"));
	printf ("	%s\n", _("<int> - Storage to check"));
	printf (" %s\n", "-T, --Type=[1-7]");
	printf ("	%s\n", _("1 - Storage percent used (default)"));
	printf ("	%s\n", _("2 - Storage percent left"));
	printf ("	%s\n", _("3 - Storage MegaBytes used"));
	printf ("	%s\n", _("4 - Storage MegaBytes left"));
	printf ("	%s\n", _("---"));
	printf ("	%s\n", _("5 - I/O load average 1 min"));
	printf ("	%s\n", _("6 - I/O load average 5 min"));
	printf ("	%s\n", _("7 - I/O load average 15 min"));
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
	
	printf (UT_SUPPORT);
}

/* process command-line arguments */
int process_arguments (int argc, char **argv)
{
	int c, option;
	int i, x;
	char *optary;
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));
	mp_snmp_finalize_auth(ctx);
	
	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"usage", no_argument, 0, 'u'},
		{"perfdata", no_argument, 0, 'f'},
		{"monitordisktype", required_argument, 0, 'm'},
		{"indexofdisk", required_argument, 0, 'i'},
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
				o_perfdata = 1;
				break;
			case 'm':
				o_monitortype = atoi(optarg);
				break;
			case 'i':
				o_get_index = atoi(optarg);
				break;
			case 'T':
				o_type = atoi(optarg);
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

	return validate_arguments ();
}

int validate_arguments (void)
{
	if (o_monitortype > 2 || o_monitortype == 0) {
		printf("Invalid input value for -m (Use 1|2).\n");
		exit(STATE_UNKNOWN);
	}
	else if (o_monitortype == 1 && o_type > 4) {
		printf("Invalid input value for -T (Use 1|2|3|4).\n");
		exit(STATE_UNKNOWN);
	}
	else if (o_monitortype == 2 && o_type < 5 || o_type > 7) {
		printf("Invalid input value for -T (Use 5|6|7).\n");
		exit(STATE_UNKNOWN);
	}
	return OK;
}

int main(int argc, char **argv)
{
	const int MBPREFIX = 1024*1024;
	static thresholds *thresh;
	struct disk_info *ptr;
	char *uom = "%"; /* used with perfdata */
	int result = STATE_UNKNOWN;
	int percent_used, percent_left;
	unsigned long long mb_used, mb_left;
	
	mp_snmp_init(program_name, 0);
	
	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);
	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* set standard monitoring-plugins thresholds utils_base.c */
	set_thresholds(&thresh, warn_str, crit_str);

	/* get, calculate and set result status */
	if (o_monitortype == 1) {
		ptr = check_disk_ret(ctx, ~0);	/* get net-snmp disk data */
		mp_snmp_deinit(program_name);	/* deinit */
		if (ptr->Descr == NULL) {
			printf("Invalid input value for -i (Use -i 0).\n");
			exit(STATE_UNKNOWN);
		}
		
		if (o_type == 1) { 		/* Percent used (default) */
			percent_used = (double)ptr->Used/(double)ptr->Size*100;
			result = get_status (percent_used, thresh);
		}
		else if (o_type == 2) {	/* Percent left */
			percent_left = (double)(ptr->Size-ptr->Used)/(double)ptr->Size*100;
			result = get_status (percent_left, thresh);
		}
		else if (o_type == 3) {	/* MegaBytes used */
			mb_used = (unsigned long long)ptr->Used*ptr->AllocationUnits/MBPREFIX;
			result = get_status (mb_used, thresh);
			uom = "MB";
		}
		else if (o_type == 4) {	/* MegaBytes left */
			mb_left = (unsigned long long)(ptr->Size-ptr->Used)*ptr->AllocationUnits/MBPREFIX;
			result = get_status (mb_left, thresh);
			uom = "MB";
		}
		else
			die(STATE_UNKNOWN, _("Could not handle -T values.\n"));
	}
	else if (o_monitortype == 2) {
		ptr = check_disk_io_ret(ctx, ~0); 	/* get net-snmp io data */
		mp_snmp_deinit(program_name);		/* deinit */
		if (ptr->IO.Descr == NULL) {
			printf("Invalid input value for -i (Use -i 0).\n");
			exit(STATE_UNKNOWN);
		}
		
		if (o_type == 5)
			result = get_status (ptr->IO.La1, thresh);
		else if (o_type == 6)
			result = get_status (ptr->IO.La5, thresh);
		else if (o_type == 7)
			result = get_status (ptr->IO.La15, thresh);
		else
			die(STATE_UNKNOWN, _("Could not handle -T values.\n"));
	}
	else
		die(STATE_UNKNOWN, _("Wrong parameter for -m(Use 1|2).\n"));
	
	/* output result state */
	if (result == STATE_OK)
			printf("OK: ");
	if (result == STATE_WARNING)
			printf("WARNING: ");
	if (result == STATE_CRITICAL)
			printf("CRITICAL: ");
	if (result == STATE_UNKNOWN)
			printf("UNKNOWN: ");

	/* output result text and values with optional perfdata */
	if (o_monitortype == 1) {
		if (o_type == 1) {
			printf("%d%s of storage used ", percent_used, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%d%s;%s;%s",
					ptr->Descr, percent_used, uom, warn_str, crit_str);
			}
		}
		else if (o_type == 2) {
			printf("%d%s of storage left ", percent_left, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%d%s;%s;%s",
					ptr->Descr, percent_left, uom, warn_str, crit_str);
			}
		}
		else if (o_type == 3) {
			printf("%lld%s of storage used ", mb_used, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%lld%s;%s;%s",
					ptr->Descr, mb_used, uom, warn_str, crit_str);
			}
		}
		else if (o_type == 4) {
			printf("%lld%s of storage left ", mb_left, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%lld%s;%s;%s",
					ptr->Descr, mb_left, uom, warn_str, crit_str);
			}
		}
		else
			die(STATE_UNKNOWN, _("Wrong parameter for -T(Use 1|2|3|4).\n"));
	}
	else if (o_monitortype == 2) {
		if (o_type == 5) {
			printf("%d%s IO Load-1 ", ptr->IO.La1, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La1,
						uom, warn_str, crit_str);
			}
		}
		else if (o_type == 6) {
			printf("%d%s IO Load-5 ", ptr->IO.La5, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La5,
						uom, warn_str, crit_str);
			}
		}
		else if (o_type == 7) {
			printf("%d%s IO Load-15 ", ptr->IO.La15, uom);
			if (o_perfdata == 1) {
				printf("|'%s'=%d%s;%s;%s", ptr->IO.Descr, ptr->IO.La15,
						uom, warn_str, crit_str);
			}
		}
		else 
			die(STATE_UNKNOWN, _("Wrong parameter for -T(Use 5|6|7).\n"));
	}
	else
		die(STATE_UNKNOWN, _("Wrong parameter for -m(Use 1|2).\n"));

	printf("\n");
	
	free(ctx);
	free(ptr);

	return result;
}
