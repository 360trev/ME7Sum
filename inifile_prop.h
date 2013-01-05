#ifndef INIFILE_PROP_H
#define INIFILE_PROP_H

#include <stdint.h>

#include "inifile/inifile.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define END_LIST	-1
#define GET_VALUE	 1
#define GET_STRING	 2


typedef struct PropertyListItem {
	int attr_type;
	uint32_t *attr_adr;
	const char *attr_path;
	const char *attr_name;
	/* const */ char *attr_default;	/* ugh. can't be const for stupid reasons */
} PropertyListItem;

uint32_t get_property_value(struct section *sections, const char *sectname, const char *propname, const char *def);
int process_properties_list(struct section *osconfig, PropertyListItem *ci);

#ifdef  __cplusplus
}
#endif

#endif

// vim:ts=4:sw=4
