//
// inifile_prop.h
//
// Property files
//
// Oriignal copyright (C) 2002 Michael Ringgaard. All rights reserved.
// Added to (C) 2012 360trev.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
// 1. Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.  
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.  
// 3. Neither the name of the project nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission. 
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
// SUCH DAMAGE.
// 

#ifndef INIFILE_H
#define INIFILE_H

struct property;

struct section
{
  char *name;
  struct section *next;
  struct property *properties;
};

struct property
{
  char *name;
  char *value;
  struct property *next;
};

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
} PropertyListItem;	

struct section *find_section(struct section *sect, char *name);
int get_section_size(struct section *sect);
char *find_property(struct section *sect, char *name);
char *get_property(struct section *sections, char *sectname, char *propname, char *defval);
int get_numeric_property(struct section *sections, char *sectname, char *propname, int defval);
void free_properties(struct section *sect);
struct section *parse_properties(char *props);
void list_properties(int f, struct section *sect);
struct section *read_properties(char *filename);
int dump_section_properties(struct section *sections, char *sectname);

uint32_t get_property_value(struct section *sections, char *sectname, char *propname, char *def);
int process_properties_list(struct section *osconfig, PropertyListItem *ci);

#ifdef  __cplusplus
}
#endif

#endif
