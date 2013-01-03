#ifndef _GETOPT_H
#define _GETOPT_H

#include "pgetopt.h"
#define getopt pgetopt
/* popterr does the WRONG thing */
static int opterr;
#define optind poptind
#define optarg poptarg
#define optopt poptopt

#endif
