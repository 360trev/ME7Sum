#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "inifile_prop.h"

uint32_t get_property_value(struct section *sections, char *sectname, char *propname, char *def)
{
	uint32_t val=0;
	uint32_t defval=0;
	char *pStr=0;

	// get default value string (if exists)
	if(def != NULL) {
		defval=strtoul(def, NULL, 16);
	}
	// lookup property
	pStr = get_property(sections, sectname, propname, NULL);
	// success?
	if(pStr != NULL) {
		// scan property value
		val=strtoul(pStr, NULL, 16);
		free(pStr);
	} else {
		val = defval;
	}
	return val;
}


int process_properties_list(struct section *osconfig, PropertyListItem *ci)
{
	int i=0,type,errCount=0;
	uint32_t *pAdr;

	while(1) {
		type = ci[i].attr_type;
		if(type == END_LIST) break;	// exit list...
		if(type == GET_VALUE) {			// process list entry for GET_VALUE type
			pAdr  = ci[i].attr_adr;
			if(pAdr != 0) {
				*pAdr = get_property_value(osconfig, ci[i].attr_path, ci[i].attr_name,	ci[i].attr_default);
				printf("get_property_value( %s, %s)\n",ci[i].attr_path,ci[i].attr_name);
				if(*pAdr == 0) { 
					errCount++;
					printf("Warning: Failed to get value for %s %s\n",ci[i].attr_path, ci[i].attr_name);
				}
			} else {
				printf("Error: Invalid storage for property, check property list definition, item %d\n",i);
			}
		} else {
			printf("Unsupported property accessor type, check propertylist, item %d\n", i);
		}
		i++;
	}
	printf("Processed %d elements with %d issues\n",i,errCount);
	return errCount;
}

// vim:ts=4:sw=4
