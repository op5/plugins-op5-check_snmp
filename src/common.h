#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>							/* obligatory includes */
#include <stdlib.h>
#include <errno.h>

/* This block provides uintmax_t - should be reported to coreutils that this should be added to fsuage.h */

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>	/* This is assumed true, because coreutils assume it too */
#include <sys/time.h>
#include <time.h>

/* GNU Libraries */
#include <getopt.h>
#include <locale.h>

/* SSL implementations */
#ifdef HAVE_GNUTLS_OPENSSL_H
#  include <gnutls/openssl.h>
#else
#  define OPENSSL_LOAD_CONF /* See the OPENSSL_config(3) man page. */
#  ifdef HAVE_SSL_H
#    include <rsa.h>
#    include <crypto.h>
#    include <x509.h>
#    include <pem.h>
#    include <ssl.h>
#    include <err.h>
#  else
#    ifdef HAVE_OPENSSL_SSL_H
#      include <openssl/rsa.h>
#      include <openssl/crypto.h>
#      include <openssl/x509.h>
#      include <openssl/pem.h>
#      include <openssl/ssl.h>
#      include <openssl/err.h>
#    endif
#  endif
#endif

/*
 *
 * Standard Values
 *
 */

enum {
	OK = 0,
	ERROR = -1
};

enum {
	STATE_OK = 0,
	STATE_WARNING = 1,
	STATE_CRITICAL = 2,
	STATE_UNKNOWN = 3,
	STATE_DEPENDENT = 4
};

#define DEFAULT_SOCKET_TIMEOUT  10   /* timeout after 10 seconds */
#define MAX_INPUT_BUFFER        8192 /* max size of most buffers we use */
#define MAX_HOST_ADDRESS_LENGTH 256  /* max size of a host address */


// Don't like this definition... should be the correct system header
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

#define _(_X) (_X)
#define NP_VERSION "FIXME"

#endif /* _COMMON_H_ */
