#ifndef INIFILE_PROP_H
#define INIFILE_PROP_H

#include "lib_ini/inifile.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define END_LIST      -1
#define GET_VALUE			1
#define GET_STRING    2
#define ATTR_MAX_PATH	64
#define ATTR_MAX_NAME	128

typedef struct PropertyListItem {
	int attr_type;
	uint32_t *attr_adr;
	char attr_path[ATTR_MAX_PATH];
	char attr_name[ATTR_MAX_NAME];
	char attr_default[ATTR_MAX_NAME];
} PropertyListItem;

uint32_t get_property_value(struct section *sections, char *sectname, char *propname, char *def);
int process_properties_list(struct section *osconfig, PropertyListItem *ci);

#ifdef  __cplusplus
}
#endif

#endif
