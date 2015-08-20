#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "common.h"
#include "utils_base.h"
#include "utils_snmp.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/* opaque structure. Modify as needed */
struct mp_snmp_context {
	char *name;
	char *auth_pass;
	char *priv_pass;
	int error;
	char *errstr;
	netsnmp_session session;
};

/** accessors **/
const netsnmp_session *mp_snmp_get_session(struct mp_snmp_context *ctx)
{
	return &ctx->session;
}

const char *mp_snmp_get_peername(struct mp_snmp_context *ctx)
{
	return ctx->session.peername;
}

int mp_snmp_get_remote_port(struct mp_snmp_context *ctx)
{
	return (int)ctx->session.remote_port;
}

const char *mp_snmp_get_errstr(struct mp_snmp_context *ctx)
{
	return (const char *)ctx->errstr;
}

int mp_snmp_is_valid_var(netsnmp_variable_list *v)
{
	if (!v || !v->name || !v->name_length)
		return 0;
	if (!v->name || !v->name_length)
		return 0;
	switch (v->type) {
	case SNMP_ENDOFMIBVIEW: case SNMP_NOSUCHOBJECT: case SNMP_NOSUCHINSTANCE:
		return 0;
	case ASN_NULL:
		return 0;
	}
	return 1;
}

int mp_snmp_query(mp_snmp_context *ctx, netsnmp_pdu *pdu, netsnmp_pdu **response)
{
	netsnmp_session *ss;
	int ret;

	if (!(ss = snmp_open(&ctx->session))) {
		snmp_sess_perror("snmp_open", &ctx->session);
		return -1;
	}
	ret = snmp_synch_response(ss, pdu, response);
	snmp_close(ss);

	return ret;
}

mp_snmp_context *mp_snmp_create_context(void)
{
	mp_snmp_context *c;
	c = calloc(1, sizeof(struct mp_snmp_context));
	if (!c)
		return NULL;

	snmp_sess_init(&c->session);
	/* set some defaults */
	c->session.version = SNMP_VERSION_2c;
	c->session.timeout = 15 * 100000;
	c->session.community = (u_char *)"public";
	c->session.community_len = (size_t)strlen((char *)c->session.community);
	return c;
}

static void _parse_key(netsnmp_session *ss, char *pass, u_char *key, size_t *len)
{
	if (*pass == '0' && pass[1] == 'x') {
		if (!snmp_hex_to_binary((u_char **)&pass, len, (size_t *)key, 0, pass)) {
			die(STATE_UNKNOWN, _("Can't convert string to hex: %s\n"), pass);
		}
	} else {
		if (generate_Ku(ss->securityAuthProto,
						ss->securityAuthProtoLen,
						(u_char *)pass, strlen(pass),
						key, len) != SNMPERR_SUCCESS)
		{
			die(STATE_UNKNOWN, _("Error generating Ku from password '%s'\n"), pass);
		}
	}
}

int mp_snmp_finalize_auth(mp_snmp_context *c)
{
	if (c->auth_pass || c->priv_pass || c->session.securityName
	    || c->session.securityPrivProtoLen || c->session.securityAuthProtoLen
	    || c->session.securityLevel)
	{
		c->session.version = SNMP_VERSION_3;
	}
	if (c->auth_pass) {
		c->session.securityAuthKeyLen = sizeof(c->session.securityAuthKey);
		_parse_key(&c->session, c->auth_pass, c->session.securityAuthKey, &c->session.securityAuthKeyLen);
	}
	if (c->priv_pass) {
		c->session.securityPrivKeyLen = sizeof(c->session.securityPrivKey);
		if (c->session.securityPrivProto == NULL) {
#ifndef NETSNMP_DISABLE_DES
			c->session.securityPrivProto = snmp_duplicate_objid(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
			c->session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#else
			c->session.securityPrivProto = snmp_duplicate_objid(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
			c->session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#endif
		}
		_parse_key(&c->session, c->priv_pass, c->session.securityPrivKey, &c->session.securityPrivKeyLen);
	}

	return 0;
}

void mp_snmp_destroy_context(struct mp_snmp_context *c)
{
	free(c->name);
	free(c->auth_pass);
	free(c->priv_pass);
	free(c);
}

void mp_snmp_argument_help(void)
{
	printf(" -H, --hostname=STRING\n");
	printf("    %s\n", _("IP address to the SNMP server"));
	printf(" -p, --port=INTEGER\n");
	printf("    %s\n", _("Port number (default: 161)"));
	printf(" -C, --community=STRING\n");
	printf("   %s\n", _("Community string for SNMP communication"));
	printf(" -P, --protocol=[1|2c|3]\n");
	printf("    %s\n", _("SNMP protocol version"));
	printf(" -L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]\n");
	printf("    %s\n", _("SNMPv3 securityLevel"));
	printf(" -U, --secname=USERNAME\n");
	printf("    %s\n", _("SNMPv3 username"));
	printf(" -a, --authproto=[MD5|SHA]\n");
	printf("    %s\n", _("SNMPv3 auth proto"));
	printf(" -A, --authpassword=PASSWORD\n");
	printf("    %s\n", _("SNMPv3 authentication password"));
	printf(" -x, --privproto=[DES|AES]\n");
	printf("    %s\n", _("SNMPv3 priv proto (default DES)"));
	printf(" -X, --privpasswd=PASSWORD\n");
	printf("    %s\n", _("SNMPv3 privacy password"));
}

int mp_snmp_handle_argument(mp_snmp_context *ctx, int option, const char *opt)
{
	char *str;

	switch (option) {
	case 'H':
		ctx->session.peername = (u_char *)opt;
		break;
	case 'p':
		ctx->session.remote_port = (unsigned short)atoi(opt);
		break;
	case 't':
		ctx->session.timeout = atoi(opt) * 1000000;
		break;
	case 'r':
		ctx->session.retries = atoi(opt);
		break;
	case 'C':
		ctx->session.community = (u_char *)opt;
		ctx->session.community_len = strlen(opt);
		break;
	case 'P':
		if (*opt == '1')
			ctx->session.version = SNMP_VERSION_1;
		else if (*opt == '2')
			ctx->session.version = SNMP_VERSION_2c;
		else if (*opt == '3')
			ctx->session.version = SNMP_VERSION_3;
		else {
			die(STATE_UNKNOWN, _("Unparsable snmp version: %s\n"), opt);
		}
		break;
		/* SNMP v3 crap goes here */
	case 'L':
		str = strdup(opt);
		ctx->session.securityLevel = parse_secLevel_conf("ignored", str);
		if (ctx->session.securityLevel < 0) {
			die(STATE_UNKNOWN, _("Invalid argument for secLevel: %s\n"), opt);
			exit(STATE_UNKNOWN);
		}
		break;
	case 'U':
		ctx->session.securityName = strdup(opt);
		ctx->session.securityNameLen = strlen(opt);
		break;
	case 'a':
		if (*opt == 'm' || *opt == 'M') {
			ctx->session.securityAuthProto = usmHMACMD5AuthProtocol;
			ctx->session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		} else if (*opt == 's' || *opt == 'S') {
			ctx->session.securityAuthProto = usmHMACSHA1AuthProtocol;
			ctx->session.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		} else {
			die(STATE_UNKNOWN, _("AuthProto must be 'md5' or 'sha1', not '%s'\n"), opt);
		}
		break;
	case 'A':
		ctx->auth_pass = strdup(opt);
		break;
	case 'x':
		if (*opt == 'd' || *opt == 'D') {
			ctx->session.securityPrivProto = usmDESPrivProtocol;
			ctx->session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		} else if (*opt == 'a' || *opt == 'A') {
			ctx->session.securityPrivProto = usmAESPrivProtocol;
			ctx->session.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
		} else {
			die(STATE_UNKNOWN, _("PrivProto requires 'des' or 'aes' as argument, not '%s'\n"), opt);
		}
		break;
	case 'X':
		ctx->priv_pass = strdup(opt);
		break;
	default:
		return -1;
	}
	return 0;
}

const char *mp_snmp_oid2str(oid *o, size_t len)
{
	static char str[2 + (MAX_OID_LEN * 4)];
	snprint_objid(str, sizeof(str) - 1, o, len);
	return str;
}

char *mp_snmp_value2str(netsnmp_variable_list *v, char *buf, size_t len)
{
	snprint_value(buf, len, v->name, v->name_length, v);
	return buf;
}

static int mp_snmp_synch_response(mp_snmp_context *ctx, netsnmp_session *ss,
		netsnmp_pdu *query, netsnmp_pdu **response)
{
	int ret;

	ret = snmp_synch_response(ss, query, response);
	if (ret != STAT_SUCCESS) {
		snmp_error(ss, &ss->s_errno, &ss->s_snmp_errno, &ctx->errstr);
		return -1;
	} else if ((*response)->errstat != SNMP_ERR_NOERROR) {
		ctx->errstr = strdup(snmp_errstring((*response)->errstat));
		return -2;
	}
	return 0;
}

int mp_snmp_walk(mp_snmp_context *ctx, const char *base_oid, const char *end_oid, mp_snmp_walker func, void *arg, void *arg2)
{
	netsnmp_session *s;
	oid name[MAX_OID_LEN];
	size_t name_length;
	oid root[MAX_OID_LEN];
	size_t root_len;
	oid end[MAX_OID_LEN];
	size_t end_len = 0;
	int count, running, status = STAT_ERROR, exitval = 0;
	int result;

	s = snmp_open(&ctx->session);

	/*
	 * get the initial object and subtree
	 */
	root_len = MAX_OID_LEN;
	if (snmp_parse_oid(base_oid, root, &root_len) == NULL) {
		die(STATE_UNKNOWN, _("Failed to add %s as root for snmpwalk: %s\n"),
		    base_oid, snmp_api_errstring(snmp_errno));
	}

	if (!end_oid) {
		memmove(end, root, root_len*sizeof(oid));
		end_len = root_len;
		end[end_len-1]++;
	} else {
		end_len = MAX_OID_LEN;
		if (snmp_parse_oid(end_oid, end, &end_len) == NULL) {
			die(STATE_UNKNOWN, _("Failed to add %s as end for snmpwalk: %s\n"),
			    end_oid, snmp_api_errstring(snmp_errno));
		}
	}

	/*
	 * get first object to start walk
	 */
	memmove(name, root, root_len * sizeof(oid));
	name_length = root_len;

	running = 1;
	while (running) {
		netsnmp_variable_list *v;
		netsnmp_pdu	*pdu, *response = NULL;
		/* create query pdu. We use GETBULK if not snmp v1 */
		if (ctx->session.version == SNMP_VERSION_1) {
			pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		} else {
			pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
			pdu->non_repeaters = 0;
			pdu->max_repetitions = 25;
		}
		snmp_add_null_var(pdu, name, name_length);

		/* do the request */
		status = snmp_synch_response(s, pdu, &response);
		if (status != STAT_SUCCESS) {
			if (status == STAT_TIMEOUT) {
				die(STATE_UNKNOWN, _("Timeout: No Response from %s\n"), s->peername);
			}
			else {
				/* status == STAT_ERROR */
				die(STATE_UNKNOWN, _("SNMP error when querying %s\n"), s->peername);
			}
			running = 0;
			exitval = 1;
			break;
		}

		if (response->errstat != SNMP_ERR_NOERROR) {
			/* error in response, print it */
			fprintf(stderr, "Error in packet.\nReason: %s\n",
					snmp_errstring(response->errstat));
			if (response->errindex != 0) {
				fprintf(stderr, "Failed object: ");
				for (count = 1, v = response->variables;
					 v && count != response->errindex;
					 v = v->next_variable, count++)
					/*EMPTY*/;
				if (v)
					fprint_objid(stderr, v->name, v->name_length);
				fprintf(stderr, "\n");
			}
			exitval = 2;
			break;
		}

		/* check resulting variables */
		for (v = response->variables; v; v = v->next_variable) {
			if (snmp_oid_compare(end, end_len, v->name, v->name_length) <= 0) {
				char v_oid[MAX_OID_LEN * 4];
				snprint_objid(v_oid, sizeof(v_oid) - 1, v->name, v->name_length);
				/* not part of this subtree */
				running = 0;
				break;
			}

			if (!mp_snmp_is_valid_var(v)) {
				running = 0;
				break;
			}

			/* found a proper variable, so handle it */
			result = func(v, arg, arg2);
			if (result == MP_SNMPWALK_STOP) {
				running = 0;
				break;
			}

			memmove((char *) name, (char *) v->name,
			        v->name_length * sizeof(oid));
			name_length = v->name_length;
		}
		if (response) {
			snmp_free_pdu(response);
			response = NULL;
		}
	}
	snmp_close(s);

	return exitval;
}

/*
 * This function takes an snmp-subtree and grabs snmp variables
 * of that subtree that are marked in the 'mask' argument, using
 * 'key' as the final entry in the oid to reach the leaf node.
 *
 * if base_oid == .1.3.6.1, mask == 5 (101, binary) and key == 9,
 * we would add .1.3.6.1.0.9 and .1.3.6.1.2.9 to be fetched by the
 * next request using *pdu, because (mask & (1 << 0)) == 1, and
 * (mask & (1 << 2)) == 1
 * This is pretty useful, since almost all snmp info requires
 * multiple variables to be fetched from a single table in order
 * to make sense of the information. This is, for example, the
 * hrStorage table for the /home partition on my laptop. In
 * this case, I would have base_oid = .1.3.6.1.2.1.25.2.3.1,
 * key = 55 and mask = 28 (binary 111000) in order to fetch
 * the blocksize, total size and used size for the home
 * partition.
 * .1.3.6.1.2.1.25.2.3.1.1.55 = INTEGER: 55
 * .1.3.6.1.2.1.25.2.3.1.2.55 = OID: .1.3.6.1.2.1.25.2.1.4
 * .1.3.6.1.2.1.25.2.3.1.3.55 = STRING: /home
 * .1.3.6.1.2.1.25.2.3.1.4.55 = INTEGER: 4096 Bytes
 * .1.3.6.1.2.1.25.2.3.1.5.55 = INTEGER: 49678626
 * .1.3.6.1.2.1.25.2.3.1.6.55 = INTEGER: 45483461
 */
int mp_snmp_add_keyed_subtree(netsnmp_pdu *pdu, const char *base_oid, int mask, int key)
{
	oid o[MAX_OID_LEN];
	size_t len = MAX_OID_LEN;
	int i = 0;

	if (key < 0)
		return key;

	memset(o, 0, sizeof(o));
	snmp_parse_oid(base_oid, o, &len);
	len++;
	o[len++] = key;
	/* snmp trees are 1-indexed, so i starts at one */
	for (i = 1; mask; i++, mask >>= 1) {
		if (!(mask & 1))
			continue;

		o[len - 2] = i;
		snmp_add_null_var(pdu, o, len);
	}
	return 0;
}

void mp_snmp_init(const char *name, int flags)
{
	/* optionally disable logging from the net-snmp library */
	if (!(flags & MP_SNMP_ENABLE_LOGS)) {
		int i;
		for (i = 0; i < LOG_DEBUG; i++) {
			(void)netsnmp_register_loghandler(NETSNMP_LOGHANDLER_NONE, i);
		}
	}

	if (!(flags & MP_SNMP_LOAD_MIBS)) {
		/* disable mib parsing. It takes a lot of resources */
		netsnmp_set_mib_directory(":");
	}

	if (!(flags & MP_SNMP_LOAD_CONFIG)) {
		netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD, 1);
	}
#if 0
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, 1);
	netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, NETSNMP_OID_OUTPUT_NUMERIC);
#endif
	init_snmp(name ? name : "mp_snmp");
}

void mp_snmp_deinit(const char *name)
{
	snmp_shutdown(name ? name : "mp_snmp");
}
