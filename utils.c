#include "utils.h"

int iload_file(struct ImageHandle *ih, const char *fname, int rw)
{
	// init image handle structure to zero's
	memset(ih, 0, sizeof(*ih));
	// load file into memory
	if(((ih->d.p)= (void *)load_file(fname,&ih->len)) == 0) return -1;
	return 0;
}

int ifree_file(struct ImageHandle *ih)
{
	if((ih->d.p) != 0) free(ih->d.p);
	memset(ih, 0, sizeof(*ih));
	return 0;
}
