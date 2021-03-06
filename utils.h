#ifndef _UTILS_H
#define _UTILS_H

#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#else
#include <endian.h>
#endif

#include "load_file.h"
#include "save_file.h"

struct ImageHandle {
	union {
//		uint32_t	*u32;
		uint16_t	*u16;
		uint8_t		*u8;
		char		*s;
		void		*p;
	} d;
	size_t	len;
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le32toh(x) (x)
#define le16toh(x) (x)
#define htole32(x) (x)
#define htole16(x) (x)
#else
#define le32toh(x) __bswap_32(x)
#define htole16(x) __bswap_16(x)
#define le32toh(x) __bswap_32(x)
#define htole16(x) __bswap_16(x)
#endif

// they're the same.
#define memcpy_to_le32 memcpy_from_le32

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define memcpy_from_le32(dest, src, len) \
	memcpy(dest, src, len)
#else
#define memcpy_from_le32(dest, src, len) { \
	int i; \
	for (i=0;i<len/4;i++) \
		((uint32_t *)dest)[i] = __bswap_32(((uint32_t *)src)[i]); \
}
#endif

int iload_file(struct ImageHandle *ih, const char *fname, int rw);
int ifree_file(struct ImageHandle *ih);

#endif
