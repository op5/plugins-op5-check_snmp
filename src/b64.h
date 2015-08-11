#include <limits.h>
char *b64_encode(unsigned char *in, size_t len);
char *b64_encodef(const char *fmt, ...)
	__attribute__((__format__(__printf__, 1, 2)));
