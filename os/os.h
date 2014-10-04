#ifndef _OS_H
#define _OS_H

#if _MSC_VER
#include "os/getopt.h"
#include <winsock2.h>	/* ntohl() */
#else
#include <getopt.h>
#include <arpa/inet.h>	/* ntohl() */
#endif

#endif
