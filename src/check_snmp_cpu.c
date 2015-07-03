/**
 * Check system memory over snmp
 * Add a big description
 */
const char *progname = "check_snmp_cpu";
const char *program_name = "check_snmp_cpu"; /* Required for coreutils libs */
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

/** 
 * UCD-SNMP-MIB laTable for cpu load on linux systems
 * 1,5 and 15 minute load averages
 * Note: Could use "6 laLoadFloat" but I'm unsure how 
 * to use the OPAQUE float value. Therefore I calculated
 * the float value in the cpu_callback function...
 */
#define LOAD_TABLE "1.3.6.1.4.1.2021.10.1.5" /* laLoadInt */
#define LOAD_SUBIDX_LaLoad1 1
#define LOAD_SUBIDX_LaLoad5 2
#define LOAD_SUBIDX_LaLoad15 3

#define SYSTEMSTATS_TABLE ".1.3.6.1.4.1.2021.11" /* Scalars */
#define SYSTEMSTATS_SUBIDX_CpuRawWait 54 	/* of type counter */

#define HRDEVICE_TABLE ".1.3.6.1.2.1.25.3.3.1" /* hrDeviceTable */
#define HRDEVICE_SUBIDX_TYPE 1

/* From check_procs.c */
int process_arguments (int, char **);
int validate_arguments (void);
void print_help (void);
void print_usage (void);

char *warning_range = NULL;
char *critical_range = NULL;
static thresholds *thresh;
mp_snmp_context *ctx;
char *warn_str = NULL, *crit_str = NULL;
int o_perfdata = 0;
char *o_loadtype = "1";

struct cpu_info {
	float Load1;
	float Load5;
	float Load15;
	
	int CpuRawWait;
	int NumberOfCpus;
};

static int cpu_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;

	switch (v->name[10]) {
		case LOAD_SUBIDX_LaLoad1:
			cc->Load1=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load1\n",cc->Load1);
			break;
		case LOAD_SUBIDX_LaLoad5:
			cc->Load5=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load5\n",cc->Load5);
			break;
		case LOAD_SUBIDX_LaLoad15:
			cc->Load15=(float)*v->val.integer/100;
			mp_debug(3,"%.2f load15\n",cc->Load15);
			break;
	}
}
static int io_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	switch (v->name[8]) {
		case SYSTEMSTATS_SUBIDX_CpuRawWait:
			cc->CpuRawWait=*v->val.integer;
			mp_debug(3,"%d Number of 'ticks' spent waiting for I/O\n",cc->CpuRawWait);
			break;
	}
}
static int type_callback(netsnmp_variable_list *v, void *cc_ptr, void *discard)
{
	struct cpu_info *cc = (struct cpu_info *)cc_ptr;
	switch (v->name[10]) {
		case HRDEVICE_SUBIDX_TYPE:
			cc->NumberOfCpus++;
			mp_debug(3,"%d CPU found\n",cc->NumberOfCpus);
			break;
	}
}

struct cpu_info *check_mem_ret(mp_snmp_context *ss, int statemask)
{
	struct cpu_info *ci = (struct cpu_info *) malloc(sizeof(struct cpu_info));
	memset(ci, 0, sizeof(struct cpu_info));
	mp_snmp_walk(ss, LOAD_TABLE, NULL, cpu_callback, ci, NULL);
	mp_snmp_walk(ss, SYSTEMSTATS_TABLE, NULL, io_callback, ci, NULL);
	mp_snmp_walk(ss, HRDEVICE_TABLE, NULL, type_callback, ci, NULL);
	
	mp_debug(3,"Load-1: %f, Load-5: %f, Load-15 %f, CpuRawWait %d\n",
				ci->Load1, ci->Load5, ci->Load15, ci->CpuRawWait);

	return ci;
}

void print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -C <snmp_community>\n",progname);
	printf ("[-w <warn_range>] [-c <crit_range>] [-t <timeout>] [-m [1|2|3|4]]\n");
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
	printf (" %s\n", "-m, --monitorcputype=[1|2|3|4]");
	printf ("	%s\n", _("1 - CPU Load-1"));
	printf ("	%s\n", _("2 - CPU Load-5"));
	printf ("	%s\n", _("3 - CPU Load-15"));
	printf ("	%s\n", _("4 - CPU I/O wait"));
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
	
	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"usage", no_argument, 0, 'u'},
		{"perfdata", no_argument, 0, 'f'},
		{"memtype", required_argument, 0, 'm'},
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
	
	mp_snmp_init(program_name, 0);
	ctx = mp_snmp_create_context();
	if (!ctx)
		die(STATE_UNKNOWN, _("Failed to create snmp context\n"));
		
	while (1) {
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			
			break;

		if (!mp_snmp_handle_argument(ctx, c, optarg)) {
			continue;
		}

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
			o_loadtype = optarg;
			break;
		}
	}
	free(optary);
	return validate_arguments ();
}

int validate_arguments (void)
{
	#if 0
	if (warn_percent == 0 && crit_percent == 0 && warn_size_bytes == 0
			&& crit_size_bytes == 0) {
		return ERROR;
	}
	else if (warn_percent < crit_percent) {
		usage4
			(_("Warning percentage should be more than critical percentage"));
	}
	else if (warn_size_bytes < crit_size_bytes) {
		usage4
			(_("Warning free space should be more than critical free space"));
	}
	#endif
	return OK;
}

int main(int argc, char **argv)
{
	char uom = '%'; /* used with perfdata */
	netsnmp_session session, *ss;
	struct cpu_info *ptr, *ioptr;
	char *state_str;
	int result = STATE_UNKNOWN;
	
	/* XXX REMOVE WHEN READY */
	mp_verbosity = 0;
	
	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* set standard monitoring-plugins thresholds */
	set_thresholds(&thresh, warn_str, crit_str);
	mp_snmp_finalize_auth(ctx);

#if 0
	ioptr = query_process(ctx, ~0);
	printf("IO pointer: %p\n",ioptr);
	printf("Load-1: %f, Load-5: %f, Load-15 %f, CpuRawWait %d\n",
				ioptr->Load1, ioptr->Load5, ioptr->Load15, ioptr->CpuRawWait);
#endif
	/* Get net-snmp memory data */
	ptr = check_mem_ret(ctx, ~0);

	/** 
	 * To check iowait we need to store the time and counter value
	 * and compare it to the previous value stored in a file.
	 */
	time_t fftime = 0, timenow = time(0);
	int ffcpurawwait = 0;
	float iowait = 0;

	FILE *dfp; /* data file pointer */
	char datafilename[] = "check_snmp_cpu_temp.data";
	dfp = fopen(datafilename, "r");
	if (dfp == NULL) {
		printf("Initializing temporary storage file %s\n", datafilename);
	}
	else {
		if (fscanf(dfp, "%d %ld", &ffcpurawwait, &fftime) == 2) {
			// printf("The values from the file are %d ticks and %ld s unixtime\n", ffcpurawwait, fftime);
			if ((timenow-fftime) == 0)
				die(STATE_UNKNOWN, _("The time interval needs to be at least one second.\n"));
			//printf("Calculated values: %d ticks div with %ld sec times %d processor\n",ptr->CpuRawWait-ffcpurawwait, (timenow-fftime), ptr->NumberOfCpus);
			iowait = (ptr->CpuRawWait-ffcpurawwait)/((timenow-fftime)*ptr->NumberOfCpus);
			mp_debug(3,"iowait: %.2f\n", iowait);
		}
	}
	dfp = fopen(datafilename, "w");
	if (dfp == NULL)
		die(STATE_UNKNOWN, _("Could not open the initialized file %s.\n"), datafilename);
	else
		fprintf(dfp, "%d %ld", ptr->CpuRawWait, timenow);
	
	/* check and output results */
	switch (*o_loadtype) {
		case '1':
			result = get_status ((float)ptr->Load1, thresh);
			break;
		case '2':
			result = get_status ((double)ptr->Load5, thresh);
			break;
		case '3':
			result = get_status ((double)ptr->Load15, thresh);
			break;
		case '4':
			result = get_status (iowait, thresh);
			break;
		default:
			usage4 (_("Could not parse arguments for m"));
			break;
	}
	
	if (result == STATE_OK) {
			printf("OK: ");
	}
	if (result == STATE_WARNING) {
			printf("WARNING: ");
	}
	if (result == STATE_CRITICAL) {
			printf("CRITICAL: ");
	}
	if (result == STATE_UNKNOWN) {
			printf("UNKNOWN: ");
	}

	switch (*o_loadtype) {
		case '1':
			printf("%.2f CPU load-1 ", (float)ptr->Load1);
			if (o_perfdata == 1) {
				printf("|'CPU load-1'=%.2f;%s;%s",
					ptr->Load1, warn_str, crit_str);
			}
			break;
		case '2':
			printf("%.2f CPU load-5 ", ptr->Load5);
			if (o_perfdata == 1) {
				printf("|'CPU load-5'=%.2f;%s;%s",
					ptr->Load5, warn_str, crit_str);
			}
			break;
		case '3':
			printf("%.2f CPU load-15 ", ptr->Load15);
			if (o_perfdata == 1) {
				printf("|'CPU load-15'=%.2f;%s;%s",
					ptr->Load15, warn_str, crit_str);
			}
			break;
		case '4':
			printf("%.2f CPU I/O wait ", iowait);
			if (o_perfdata == 1) {
				printf("|'CPU I/O wait'=%.2f;%s;%s",
					iowait, warn_str, crit_str);
			}
			break;
		default:
			die(STATE_UNKNOWN, _("Could not print the right output.\n"));
			break;
	}
	printf("\n");
	
	free(ctx);
	free(ptr);
	mp_snmp_deinit(program_name);

	return result;
}

#if 0
struct cpu_info *query_process(mp_snmp_context *ctx, int k)
{
	struct cpu_info *qp = (struct cpu_info *) malloc(sizeof(struct cpu_info));
	memset(qp, 0, sizeof(struct cpu_info));

	netsnmp_pdu *pdu, *response = NULL;
	netsnmp_variable_list *v;
	int mask=0, count=0;
	//struct cpu_info *p;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!pdu) {
		return NULL;
	}

	MP_SNMP_PDU_MASK_ADD(mask, LOAD_SUBIDX_LaLoad1);
	MP_SNMP_PDU_MASK_ADD(mask, LOAD_SUBIDX_LaLoad5);
	MP_SNMP_PDU_MASK_ADD(mask, LOAD_SUBIDX_LaLoad15);
	mp_snmp_add_keyed_subtree(pdu, LOAD_TABLE, mask, k);
	mask = 0;
	MP_SNMP_PDU_MASK_ADD(mask, SYSTEMSTATS_SUBIDX_CpuRawWait);
	mp_snmp_add_keyed_subtree(pdu, SYSTEMSTATS_TABLE, mask, k);
	if (mp_snmp_query(ctx, pdu, &response)) {
		die(STATE_UNKNOWN, _("Failed to fetch variables for process %d\n"), k);
	}
	if (!(qp = calloc(1, sizeof(*qp)))) {
		snmp_free_pdu(response);
		snmp_free_pdu(pdu);
		die(STATE_UNKNOWN, _("Failed to allocate memory"));
	}
	
	printf("Before loop: %p, next %p\n",v = response->variables, v=v->next_variable);
	for (v = response->variables; v; v = v->next_variable, count++) {
	printf("seg4\n");
		if (v->name[7] == 5) {
			printf("inside\n");
			/* procperf table */
			if (v->name[10] == SYSTEMSTATS_SUBIDX_CpuRawWait) {
				qp->CpuRawWait = *v->val.integer;
				printf("\n new function! \n");
			}
		}
		printf("seg5\n");
		switch (v->name[10]) {
			case LOAD_SUBIDX_LaLoad1:
				qp->Load1=(float)*v->val.integer/100;
				mp_debug(3,"\n%f load1\n",qp->Load1);
				break;
			case LOAD_SUBIDX_LaLoad5:
				qp->Load5=(float)*v->val.integer/100;
				mp_debug(3,"\n%f load5\n",qp->Load5);
				break;
			case LOAD_SUBIDX_LaLoad15:
				qp->Load15=(float)*v->val.integer/100;
				mp_debug(3,"\n%f load15\n",qp->Load15);
				break;
		}
	}
	printf("seg6\n");
	snmp_free_pdu(response);
	return qp;
}
#endif
