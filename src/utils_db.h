#include <stdlib.h>

int mp_save(void *data, size_t len, const char *path_fmt, ...);
void *mp_load(size_t *len, const char *path_fmt, ...);
