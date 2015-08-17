#include "utils_db.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "utils.h"

int mp_save(void *data, size_t len, const char *path_fmt, ...)
{
	va_list ap;
	char *path;
	int fd, ret;

	if (!len || !data || !path_fmt)
		return -1;

	va_start(ap, path_fmt);
	xvasprintf(&path, path_fmt, ap);
	va_end(ap);

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return fd;

	ret = write(fd, data, len);
	if (ret < 0)
		return ret;
	if (ret != len)
		return -1;

	(void)close(fd);
	return 0;
}

void *mp_load(size_t *len, const char *path_fmt, ...)
{
	va_list ap;
	char *path;
	int fd, ret;
	struct stat st;
	void *data;

	if (!len || !path_fmt)
		return NULL;

	va_start(ap, path_fmt);
	xvasprintf(&path, path_fmt, ap);
	va_end(ap);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = fstat(fd, &st);
	if (ret < 0) {
		close(fd);
		return NULL;
	}

	*len = st.st_size;
	data = calloc(1, st.st_size);
	if (!data) {
		close(fd);
		return NULL;
	}

	ret = read(fd, data, st.st_size);
	if (ret < 0)
		return NULL;
	if (ret != st.st_size)
		return NULL;

	close(fd);

	return data;
}
