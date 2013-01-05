#ifndef _OS_H
#define _OS_H

#if _MSC_VER
#define snprintf _snprintf
#include "os/getopt.h"
#else
#include <getopt.h>
#endif

#endif
