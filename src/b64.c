#include "utils.h"
#include <stdlib.h>
#include <stdarg.h>
#include "b64.h"

static const char *encmap = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encodef(const char *fmt, ...)
{
	char *str = NULL, *out;
	int len;
	va_list ap;

	if (!fmt)
		return NULL;

	va_start(fmt, ap);
	len = xvasprintf(&str, fmt, ap);
	va_end(ap);
	if (len < 0 || str == NULL)
		return NULL;

	out = b64_encode(str, len);
	free(str);

	return out;
}

char *b64_encode(unsigned char *in, size_t len)
{
	char *out;
	size_t i, j, outlen = ((len * 4) / 3) + 4;

	if (!(out = calloc(1, outlen)))
		return NULL;

	for (i = j = 0; i < len; i += 3) {
		const unsigned char i0 = len - i > 0 ? in[i + 0] : 0;
		const unsigned char i1 = len - i > 1 ? in[i + 1] : 0;
		const unsigned char i2 = len - i > 2 ? in[i + 2] : 0;
		out[j++] = encmap[i0 >> 2];
		out[j++] = encmap[((i0 & 0x03) << 4) | ((i1 & 0xf0) >> 4)];
		if (!i1) {
			out[j++] = '=';
			return out;
		}
		out[j++] = encmap[((i1 & 0x0f) << 2) | ((i2 & 0xc0) >> 6)];
		if (!i2) {
			out[j++] = '=';
			return out;
		}
		out[j++] = encmap[((i2 & 0x3f))];
	}

	out[j++] = '=';

	return out;
}
