#include <fcntl.h>	/* open() */
#ifdef _WIN32
#include "os/mmap.h"
#else
#include <unistd.h>	/* close() */
#include <sys/mman.h>
#endif
#include <sys/stat.h>

#include "utils.h"

int mmap_file(struct ImageHandle *ih, const char *fname, int rw)
{
	int fd;
	struct stat buf;
	void *p;

	memset(&buf, 0, sizeof(buf));
	memset(ih, 0, sizeof(*ih));

	if((fd = open(fname, rw ? O_RDWR : O_RDONLY)) < 0)
		return -1;

	if(fstat(fd, &buf))
	{
		close(fd);
		return -1;
	}

	p = mmap(NULL, buf.st_size, rw?PROT_READ|PROT_WRITE:PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED)
	{
		close(fd);
		return -1;
	}

	close(fd);

	ih->d.p=p;
	ih->len=buf.st_size;

	return 0;
}

int munmap_file(struct ImageHandle *ih)
{
	int ret=munmap(ih->d.p, ih->len);
	memset(ih, 0, sizeof(*ih));
	return ret;
}
