/**
 * @file utils_snmp.h
 * @brief SNMP utilities
 *
 * This file provides helpers for applications that want to fetch
 * data from SNMP-enabled devices.
 * @{
 */

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

/* we have to define this for our headers to build against Net-SNMP */
#define NETSNMP_NO_AUTOCONF_DEFINES

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/** return this from an mp_snmp_walker to make mp_snmp_walk() stop */
#define MP_SNMPWALK_STOP 1

/** for mp_snmp_init(). Set this to load mibs */
#define MP_SNMP_LOAD_MIBS   (1 << 0)
/** for mp_snmp_init(). Set this to load snmp configuration */
#define MP_SNMP_LOAD_CONFIG (1 << 1)
/** for mp_snmp_init(). Set this to enable logging */
#define MP_SNMP_ENABLE_LOGS (1 << 2)

#define MP_SNMP_LONGOPTS \
	{"hostname", required_argument, 0, 'H'}, \
	{"port", required_argument, 0, 'p'}, \
	{"community", required_argument, 0, 'C'}, \
	{"version", required_argument, 0, 'v'},   \
	{"retries", required_argument, 0, 'r'},   \
	{"seclevel", required_argument, 0, 'L'},  \
	{"secname", required_argument, 0, 'U'},   \
	{"authprot", required_argument, 0, 'a'},  \
	{"authpass", required_argument, 0, 'A'},  \
	{"privprot", required_argument, 0, 'P'},  \
	{"privpass", required_argument, 0, 'X'}


/** used to add entries to the 'mask' option for mp_snmp_pdu_add_subentries */
#define MP_SNMP_PDU_MASK_ADD(mask, x) (mask |= (1 << (x - 1)))

/** forward declaration for opaque structure */
struct mp_snmp_context;
typedef struct mp_snmp_context mp_snmp_context;

/** the third argument to mp_snmp_walk */
typedef int (*mp_snmp_walker)(netsnmp_variable_list *, void *, void *);

/** accessor functions */
static netsnmp_session *mp_snmp_get_session(struct mp_snmp_context *ctx);
const char *mp_snmp_get_peername(struct mp_snmp_context *ctx);
int mp_snmp_get_remote_port(struct mp_snmp_context *ctx);

/** real functions */
void mp_snmp_argument_help(void);
int mp_snmp_finalize_auth(mp_snmp_context *c);
mp_snmp_context *mp_snmp_create_context(void);
void mp_snmp_destroy_context(mp_snmp_context *ctx);
int mp_snmp_handle_argument(mp_snmp_context *ctx, int option, const char *opt);
int mp_snmp_is_valid_var(netsnmp_variable_list *v);

/**
 * Convert an oid to a string
 *
 * @param o The oid. Must not be NULL
 * @param len The length of the OID. Must be > 0.
 * @return A statically allocated char array
 */
const char *mp_snmp_oid2str(oid *o, size_t len);

/**
 * Get a string value from an SNMP variable.
 * If v is actually a list, the first item in the list is used to
 * get the value. The returned string must be free()'d.
 * If buffer is smaller than v->val.len, the behaviour is undefined
 *
 * @param v The snmp variable to get a string from
 * @param buf The buffer to print into
 * @param len Length of the buffer
 * @return The value of v as a nul-terminated character array
 */
char *mp_snmp_value2str(netsnmp_variable_list *v, char *buf, size_t len);

/**
 * Perform a walk over a series of OID's, starting with base_oid
 * This function will stop walking if "func" returns MP_SNMPWALK_STOP.
 * It's very handy for finding the index of a particular element in
 * a specific table.
 * @note The callback function will be called once for each variable
 * found. If the callback function is passed a list, it must only
 * look at the topmost item, as it will be called with the next item
 * directly after.
 * If end_oid is NULL, we will fetch all of base_oid.* and nothing
 * more, so a request to walk (base=".1.3.6.1.2.1.25.4", end="NULL")
 * will stop when we hit the first entry in .1.3.6.1.2.1.25.5.
 *
 * @param context The context for the current session
 * @param base_oid The oid where we should start walking
 * @param end_oid The oid where we should stop walking.
 * @param func The function to call for each variable found
 * @param arg First pointer passed to callback function
 * @param arg2 Second pointer passed to callback function
 * @return 0 on success. -1 on parameter errors
 */
int mp_snmp_walk(mp_snmp_context *ctx, const char *base_oid, const char *end_oid,
	mp_snmp_walker func, void *arg, void *arg2);

/**
 * Helps prepare a request pdu by adding entries to the request
 * that are set in the 'mask' parameter.
 *
 * if base_oid == .1.3.6.1, mask == 5 (101, binary) and key == 9,
 * we would add .1.3.6.1.0.9 and .1.3.6.1.2.9 to be fetched by the
 * next request using *pdu, because (mask & (1 << 0)) == 1, and
 * (mask & (1 << 2)) == 1
 * This is useful since almost all snmp info requires
 * multiple variables to be fetched from a single entry in order
 * to make sense of the information. This is, for example, the
 * hrStorage table for the /home partition on my laptop. In
 * this case, I would have base_oid = ".1.3.6.1.2.1.25.2.3.1",
 * key = 55 and mask = 28 (binary 111000) in order to fetch
 * the blocksize, total size and used size for the home
 * partition.
 * .1.3.6.1.2.1.25.2.3.1.1.55 = INTEGER: 55
 * .1.3.6.1.2.1.25.2.3.1.2.55 = OID: .1.3.6.1.2.1.25.2.1.4
 * .1.3.6.1.2.1.25.2.3.1.3.55 = STRING: /home
 * .1.3.6.1.2.1.25.2.3.1.4.55 = INTEGER: 4096 Bytes
 * .1.3.6.1.2.1.25.2.3.1.5.55 = INTEGER: 49678626
 * .1.3.6.1.2.1.25.2.3.1.6.55 = INTEGER: 45483461
 * The code to prep the mask would look something like this:
 * #define DSK_BLKSIZE_ENTRY  4
 * #define DSK_TOTSIZE_ENTRY  5
 * #define DSK_USEDSIZE_ENTRY 6
 * mask = (1 << (DSK_BLKSIZE_ENTRY - 1)) \
 *		| (1 << (DSK_TOTSIZE_ENTRY - 1)) \
 *		| (1 << (DSK_USEDSIZE_ENTRY - 1))
 * @return 0 on succes, < 0 on errors
 */
int mp_snmp_add_keyed_subtree(netsnmp_pdu *pdu,
	const char *base_oid, int mask, int key);

/**
 * Initialize the mp_snmp utilities
 *
 * @param name The name we pass to snmp_init. Can be NULL
 * @param flags Bitmask determining which parts of net-snmp we init
 */
void mp_snmp_init(const char *name, int flags);

/**
 * Close the mp_snmp_session() and release all memory
 * @param name The same name you passed to mp_snmp_init. Can be NULL
 */
void mp_snmp_deinit(const char *name);
/** @} */
