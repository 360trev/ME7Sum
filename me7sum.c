/* me7sum [ firmware management tool for Bosch ME7.x firmware]
   By 360trev and nyet

   Inspired by work from Andy Whittaker's (tools and information)
   See http://www.andywhittaker.com/ECU/BoschMotronicME71.aspx

   Note: Uses configuration files (see my ini file example)

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
   AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
   OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
   IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>	/* isprint() */

#include "os/os.h"

#include "inifile_prop.h"
#include "crc32.h"
#include "str.h"
#include "utils.h"
#include "md5.h"
#include "rsa.h"

//#define DEBUG_ROM_INFO
//#define DEBUG_RSA_MATCHING
//#define DEBUG_ROMSYS_MATCHING
//#define DEBUG_CRC_MATCHING
//#define DEBUG_MAIN_MATCHING
//#define DEBUG_MULTIPOINT_MATCHING

#include "debug.h"

#define CHECK_BOOTROM_MP
#define RSA_BLOCK_SIZE	1024

/* Images with 2+64 main mp descriptors do not have an end marker */
#ifdef CHECK_BOOTROM_MP
#define MAX_MP_BLOCK_LEN 66
#else
#define MAX_MP_BLOCK_LEN 64
#endif

// structures
struct Range {
	uint32_t	start;
	uint32_t	end;
};

struct ChecksumPair {
	uint32_t	v;	// value
	uint32_t	iv;	// inverse value
};

struct MultipointDescriptor {
	struct Range            r;
	struct ChecksumPair     csum;
};

#define MAX_CRC_BLKS 4
#define MD5_MAX_BLKS 4
// main firmware checksum validation
struct rom_config {
	int			readonly;
	uint32_t	base_address;				/* rom base address */

	struct {
		uint8_t signature[RSA_BLOCK_SIZE/8];
		uint8_t modulus[RSA_BLOCK_SIZE/8];
		int public_exponent;
		uint8_t default_signature[RSA_BLOCK_SIZE/8];
		struct Range md5[MD5_MAX_BLKS];
	} rsa;
	uint32_t	romsys;

	uint32_t	multipoint_block_start[2];	/* start of multipoint block descriptors (two sets, first one isn't always there) */
	uint32_t	multipoint_desc_len;		/* size of descriptors */
	uint32_t	main_checksum_offset;		/* two start/end pairs, one at offset, other at offset+8 */
	uint32_t	main_checksum_final;		/* two 4 byte checksum (one inv) for two blocks conctatenated above) */
	struct {
		struct Range r;
		uint32_t	offset;
	} crc[MAX_CRC_BLKS+1];					/* 0/4 is pre-region (for kbox and other) Up to 5 CRC blocks (total) to check */
	uint32_t	csm_offset;				/* ME7.1.1 */
};

struct info_config {
	InfoItem	EPK;
	InfoItem	part_number;
	InfoItem	engine_id;
	InfoItem	sw_version;
	InfoItem	hw_number;
	InfoItem	sw_number;
};

// globals
static struct rom_config Config;
static struct info_config InfoConfig;
#ifdef DEBUG_YES
static int Verbose = 2;
#else
static int Verbose = 0;
#endif

static int ChecksumsFound = 0;
static int ErrorsUncorrectable = 0;
static int ErrorsFound = 0;
static int ErrorsCorrected = 0;

//
// List of configurable properties to read from config file into our programme...
// [this stops us having to hardcode values into the code itself]
//
static PropertyListItem romProps[] = {
	// get rom region information
	{	GET_VALUE,  &Config.base_address,			"ignition", "rom_firmware_start",		"0x800000"},
	{	GET_VALUE,  &Config.multipoint_block_start[0],	"ignition", "rom_checksum_block_start0",	"0"},
	{	GET_VALUE,  &Config.multipoint_block_start[1],	"ignition", "rom_checksum_block_start",	"0"},
	{	GET_VALUE,  &Config.multipoint_desc_len,	"ignition", "rom_checksum_desc_len",	"0x10"},
	{	GET_VALUE,  &Config.main_checksum_offset,	"ignition", "rom_checksum_offset",		"0"},
	{	GET_VALUE,  &Config.main_checksum_final,	"ignition", "rom_checksum_final",		"0"},
	{	GET_VALUE,  &Config.crc[0].r.start,			"ignition", "rom_crc0_start",			"0"},
	{	GET_VALUE,  &Config.crc[0].r.end,			"ignition", "rom_crc0_end",				"0"},
	{	GET_VALUE,  &Config.crc[1].r.start,			"ignition", "rom_crc1_start",			"0"},
	{	GET_VALUE,  &Config.crc[1].r.end,			"ignition", "rom_crc1_end",				"0"},
	{	GET_VALUE,  &Config.crc[1].offset,			"ignition", "rom_crc1",					"0"},
	{	GET_VALUE,  &Config.crc[2].r.start,			"ignition", "rom_crc2_start",			"0"},
	{	GET_VALUE,  &Config.crc[2].r.end,			"ignition", "rom_crc2_end",				"0"},
	{	GET_VALUE,  &Config.crc[2].offset,			"ignition", "rom_crc2",					"0"},
	{	GET_VALUE,  &Config.crc[3].r.start,			"ignition", "rom_crc3_start",			"0"},
	{	GET_VALUE,  &Config.crc[3].r.end,			"ignition", "rom_crc3_end",				"0"},
	{	GET_VALUE,  &Config.crc[3].offset,			"ignition", "rom_crc3",					"0"},
	{	GET_VALUE,  &Config.crc[4].r.start,			"ignition", "rom_crc4_start",			"0"},
	{	GET_VALUE,  &Config.crc[4].r.end,			"ignition", "rom_crc4_end",				"0"},
	{	GET_VALUE,  &Config.crc[4].offset,			"ignition", "rom_crc4",					"0"},
	{ END_LIST,   0, "",""},
};

static InfoListItem romInfo[] = {
	// get rom region information
	{	"EPK",			GET_VALUE, &InfoConfig.EPK,			"info", "epk",			"0", "41"},
	{	"Part Number",	GET_VALUE, &InfoConfig.part_number,	"info", "part_number",	"0", "12"},
	{	"Engine ID",	GET_VALUE, &InfoConfig.engine_id,	"info", "engine_id",	"0", "17"},
	{	"SW Version",	GET_VALUE, &InfoConfig.sw_version,	"info", "sw_version",	"0", "4"},
	{	"HW Number",	GET_VALUE, &InfoConfig.hw_number,	"info", "hw_number",	"0", "10"},
	{	"SW Number",	GET_VALUE, &InfoConfig.sw_number,	"info", "sw_number",	"0", "10"},
	{ NULL,END_LIST,NULL,NULL,NULL}
};

static int GetRomDump(const struct ImageHandle *ih, struct section *osconfig);
static int GetRomInfo(const struct ImageHandle *ih, struct section *osconfig);

static int FindROMSYS(struct ImageHandle *ih);
static int DoROMSYS(struct ImageHandle *ih);

static int FindRSAOffsets(struct ImageHandle *ih);
static int FindMD5Ranges(struct ImageHandle *ih);
static int DoRSA(struct ImageHandle *ih);

static int FindMainCRCPreBlk(const struct ImageHandle *ih);
static int FindMainCRCBlks(const struct ImageHandle *ih);
static int FindMainCRCOffsets(const struct ImageHandle *ih);
static int FindMainCSMOffsets(const struct ImageHandle *ih);
static int DoMainCRCs(struct ImageHandle *ih);
static int DoMainCSMs(struct ImageHandle *ih);

static int FindMainProgramOffset(const struct ImageHandle *ih);
static int FindMainProgramFinal(const struct ImageHandle *ih);
static int DoMainChecksum(struct ImageHandle *ih, uint32_t nOffset, uint32_t nCsumAddr);

static int FindChecksumBlks(const struct ImageHandle *ih, int which);
static int DoChecksumBlk(struct ImageHandle *ih, uint32_t nStartBlk, struct strbuf *buf, int bootrom);

static void usage(const char *prog)
{
	printf("Usage: %s [-v] [-i <config.ini>] <inrom.bin> [outrom.bin]\n", prog);
	exit(-1);
}

static int bytecmp(const void *buf, uint8_t byte, size_t len)
{
	int i;
	const uint8_t *p=buf;
	for(i=0;i<len;i++) {
		if (p[i]!=byte)
			return p[i]-byte;
	}
	return 0;
}

#ifdef CHECK_BOOTROM_MP
/* returns 0 if desc[0] and [1] not in bootrom */
/* returns 1 if desc[0] and [1] are in bootrom, updates ih->bootrom_whitelist if whitelisted */
/* returns -1 if not in whitelist AND does not match next pair of non-bootrom descriptors */
static int check_whitelist(struct ImageHandle *ih, uint32_t addr)
{
	struct MultipointDescriptor desc[4];
	/* Check for hardcoded bootrom csums... if there, treat as ok */
	static const uint32_t whitelist[][2] = {{0x0fa0f5cf, 0x0f4716b3},
										    {0x0e59d5c8, 0x1077fb35}};
	int i;

	for(i=0;i<4;i++)
		memcpy_from_le32(desc+i, ih->d.u8+addr+Config.multipoint_desc_len*i,
			sizeof(struct MultipointDescriptor));

	for(i=0;i<2;i++) {
		if (desc[i].r.start>=desc[i].r.end) return 0;
		if (desc[i].r.start>=Config.base_address) return 0;
		if (desc[i].r.end>=Config.base_address) return 0;
	}

	if (desc[0].r.start!=0 || desc[0].r.end!=0x3fff) return 0;
	if (desc[1].r.start!=0x4000 || desc[1].r.end!=0x7fff) return 0;

	for(i=0;i<2;i++) {
		if (desc[0].csum.v==~desc[0].csum.iv &&
			desc[1].csum.v==~desc[1].csum.iv &&
			whitelist[i][0]==desc[0].csum.v &&
			whitelist[i][1]==desc[1].csum.v) {
			ih->bootrom_whitelist=1;
			return 1;
		}
	}

	if ((desc[0].csum.v != desc[2].csum.v) ||
		(desc[1].csum.v != desc[3].csum.v) ||
		(desc[0].csum.iv != desc[2].csum.iv) ||
		(desc[1].csum.iv != desc[3].csum.iv)) {
		printf("ERROR! Inconsistency in non-whitelisted bootrom multipoint descriptors!\n");
		ErrorsUncorrectable++;
		return -1;
	}

	return 1;
}
#endif

/*
 * main()
 *
 */
int main(int argc, char **argv)
{
	int Step=0;
	int	iTemp;
	char *prog=argv[0];
	char *inifile=NULL;
	char *input=NULL;
	char *output=NULL;
	int i, c;
	struct ImageHandle ih;
	struct section *osconfig=NULL;
	struct strbuf buf;

	memset(&buf, 0, sizeof(buf));

	// information about the tool
	printf("ME7Tool (%s) [Management tool for Bosch ME7.x firmwares]\n",
		__GIT_VERSION);
	printf("Inspiration from Andy Whittaker's tools and information\n");
	printf("Written by 360trev and nyet [BSD License Open Source].\n");

	opterr=0;

	while ((c = getopt(argc, argv, "qvi:")) != -1)
	{
		switch (c)
		{
			case 'q':
				Verbose--;
				break;
			case 'v':
				Verbose++;
				break;
			case 'i':
				inifile=optarg;
				break;
			case '?':
				if (optopt == 'i')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Unknown option '-%c'.\n", optopt);
				// break; // fallthrough
			default:
				usage(prog);
				return -1;
		}
	}

	if (Verbose<0) Verbose=0;

	argc-=optind;
	argv+=optind;

	if (argc==0 || argc>2)
		usage(prog);

	input = argv[0];

	if (argc>1)
		output = argv[1];
	else
		Config.readonly=1;

	if (inifile)
	{
		printf("Attempting to open firmware config file '%s'\n",inifile);
		// load properties file into memory
		osconfig = read_properties(inifile);
		if(osconfig == NULL)
		{
			printf("failed to open config file\n");
			return -1;
		}
	}

	// get rom region information from config file (see defined property list)
	process_properties_list(osconfig, romProps);
	process_info_list(osconfig, romInfo);

	// open the firmware file
	printf("\nAttempting to open firmware file '%s'\n",input);
	i=iload_file(&ih, input, 0, &buf);
	if (buf.pbuf) {
		if (i || Verbose>1) printf("%s", buf.pbuf);
		free(buf.pbuf);
	}
	if (i)
	{
		printf("Failed to open firmware file '%s'\n",input);
		ErrorsFound++;
		goto out;
	}

	// sanity check: validate firmware file is at least 512kbytes length before proceeding.
	if(ih.len != 512*1024 && ih.len != 1024*1024)
	{
		printf("File is an odd size (%d bytes). Are you sure this is a firmware dump?\n",
			(int)ih.len);
		ErrorsFound++;
		goto out;
	}

	if(ih.len == (1024*1024))
	{
		/* Check to make sure it isn't a doubled up file or padded
		   with ff or 00 */
		if (memcmp(ih.d.u8, ih.d.u8+512*1024, 512*1024)==0) {
			printf("File is doubled up 512k dump. Treating as 512k\n");
				ih.len=512*1024;
			ih.pad = PADDING_DOUBLED;
		} else if (bytecmp(ih.d.u8+512*1024, 0xff, 512*1024)==0) {
			printf("File is padded from 512k to 1024k with 0xFF. Treating as 512k\n");
				ih.len=512*1024;
			ih.pad = PADDING_FF;
		} else if (bytecmp(ih.d.u8+512*1024, 0xff, 512*1024-32)==0) {
			printf("File is padded from 512k to 1024k with 0xFF. Treating as 1024k but will try 512k CRC hardcoded blocks\n");
			ih.pad = PADDING_TRY_512K_CRC;
/*
		} else if (bytecmp(ih.d.u8+512*1024, 0, 512*1024)==0) {
			printf("File is padded from 512k to 1024k with zeros. Treating as 512k\n");
				ih.len=512*1024;
			ih.pad = PADDING_00;
*/
		}
	}

	GetRomInfo(&ih, osconfig);
	GetRomDump(&ih, osconfig);

	DEBUG_EXIT_ROM;

	//
	// Step #1 ROMSYS
	//
	printf("\nStep #%d: Reading ROMSYS ..\n", ++Step);

	if(Config.romsys==0)
	{
		FindROMSYS(&ih);
	}

	if(Config.romsys)
	{
		DoROMSYS(&ih);
	}
	else
	{
		printf("Step #%d: ERROR! Skipping ROMSYS.. UNDEFINED\n", Step);
		ErrorsUncorrectable++;
	}

	DEBUG_EXIT_ROMSYS;

	//
	// Step #2 RSA
	//
	printf("\nStep #%d: Reading RSA signatures ..\n", ++Step);

	FindRSAOffsets(&ih);
	if(Config.rsa.public_exponent>0) {
		FindMD5Ranges(&ih);
		if (Config.rsa.md5[0].start && Config.rsa.md5[0].end) {
			DoRSA(&ih);
		} else {
			printf("Step #%d: ERROR! Detected RSA signature, but no MD5 regions\n", Step);
			ErrorsUncorrectable++;
		}
	}
	DEBUG_EXIT_RSA;


	//
	// Step #3 Main data checksums if specified
	//
	printf("\nStep #%d: Reading Main Data Checksums ..\n", ++Step);

	if(Config.crc[0].r.start==0 && Config.crc[0].r.end==0)
	{
		FindMainCRCPreBlk(&ih);
	}

	if(Config.crc[1].r.start==0 && Config.crc[1].r.end==0)
	{
		FindMainCRCBlks(&ih);
	}

	// note, crc0 and crc4 don't have offsets!
	if(Config.crc[1].offset==0)
	{
		FindMainCRCOffsets(&ih);	/* Detect if using CRC algo */
	}

	if(Config.crc[1].offset==0 && Config.csm_offset==0)
	{
		FindMainCSMOffsets(&ih);	/* Detect if using Checksum algo */
	}

	if(Config.crc[1].r.start && Config.crc[1].r.end && Config.crc[1].offset)
	{
		DoMainCRCs(&ih);
	}
	else if (Config.crc[1].r.start && Config.crc[1].r.end && Config.csm_offset)
	{
		DoMainCSMs(&ih);
	}
	else
	{
		printf("\nStep #%d: ERROR! Skipping main data checksums ... UNDEFINED\n",
			Step);
#ifdef DEBUG_CRC_MATCHING
		DoMainCRCs(&ih);
		DoMainCSMs(&ih);
#endif
		ErrorsUncorrectable++;
	}

	DEBUG_EXIT_CRC;

	//
	// Step #4 Main program checksums
	//
	printf("\nStep #%d: Reading Main Program Checksums ..\n", ++Step);
	if(Config.main_checksum_offset==0)
	{
		FindMainProgramOffset(&ih);
	}

	if(Config.main_checksum_final==0)
	{
		FindMainProgramFinal(&ih);
	}

	if (Config.main_checksum_offset && Config.main_checksum_final)
	{
		DoMainChecksum(&ih, Config.main_checksum_offset, Config.main_checksum_final);
	}
	else
	{
		printf("Step #%d: ERROR! Skipping Main Program Checksums.. UNDEFINED\n", Step);
		ErrorsUncorrectable++;
	}

	DEBUG_EXIT_MAIN;

	//
	// Step #5 Multi point checksums
	//
	printf("\nStep #%d: Reading Multipoint Checksum Blocks ..\n", ++Step);

	for (i=0;i<2;i++) {
		if(Config.multipoint_block_start[i]==0)
		{
			FindChecksumBlks(&ih, i);
		}

		if(Config.multipoint_block_start[i])
		{
			int bootrom=0;

#ifdef CHECK_BOOTROM_MP
			/* Only check for whitelist in main multipoint block */
			if (i==1)
				bootrom = check_whitelist(&ih, Config.multipoint_block_start[i]);
#endif

			/* Images with 2+64 main MP descriptors do not have an end marker */
			for(iTemp=0; iTemp<MAX_MP_BLOCK_LEN; iTemp++)
			{
				int result=0;
				struct strbuf buf;

				if (iTemp>1) bootrom=0;

				memset(&buf, 0, sizeof(buf));
				sbprintf(&buf, "%2d) ",iTemp+1);
				result = DoChecksumBlk(&ih,
					Config.multipoint_block_start[i]+(Config.multipoint_desc_len*iTemp),
					&buf, bootrom);
				if (buf.pbuf) {
					if (iTemp<4 || result<0 || Verbose>0) printf("%s", buf.pbuf);
					free (buf.pbuf);
				}

				if (result == 1) { break; } // end of blocks;
			}
			printf(" Multipoint #%d: [%d blocks x <16> = %d bytes]\n", i+1, iTemp, iTemp*16);
		}
		else
		{
			if (i!=0) {
				printf("Step #%d: ERROR! Skipping Multipoint Checksum Block... UNDEFINED\n", Step);
				ErrorsUncorrectable++;
			}
		}
	}

	DEBUG_EXIT_MULTIPOINT;

	printf("\n*** Found %d checksums in %s\n", ChecksumsFound, input);

	if(ErrorsUncorrectable)
	{
		printf("\n*** ABORTING! %d uncorrectable error(s) in %s! ***\n", ErrorsUncorrectable, input);
		return -1;
	}

	if(output && ErrorsCorrected > 0)
	{
		struct strbuf buf;

		memset(&buf, 0, sizeof(buf));
		printf("\nAttempting to output corrected firmware file '%s'\n",output);
		// write crc corrected file out
		if (ih.pad == PADDING_DOUBLED) {
			memcpy(ih.d.u8, ih.d.u8+512*1024, 512*1024);
		}
		save_file(output,ih.d.p,ih.pad==PADDING_NONE?ih.len:ih.len*2, &buf);
		if(buf.pbuf) {
			printf("%s", buf.pbuf);
			free(buf.pbuf);
		}
	}

out:

	// close the file
	if(ih.d.p != 0) { ifree_file(&ih); }

	// free config
	if(osconfig != 0) { free_properties(osconfig); }


	if (ErrorsCorrected!=ErrorsFound) {
		printf("\n*** WARNING! %d/%d uncorrected error(s) in %s! ***\n",
			ErrorsFound-ErrorsCorrected, ErrorsFound, input);
	} else {
		printf("\n*** DONE! %d/%d error(s) corrected in %s! ***\n", ErrorsCorrected,
			ErrorsFound, input);
	}

	return 0;
}

/*
 * GetRomInfo
 *
 * - uses config file to parse rom data and show interesting information about this rom dump
 */

static int GetRomInfo(const struct ImageHandle *ih, struct section *osconfig)
{
	InfoListItem *info;
	int max_len=0;

	if(ih == NULL) return(-1);

	// Find the longest label so we know how big the label column should be
	for(info=romInfo; info->attr_type!=END_LIST; info++)
	{
		if(info->item->off && info->item->len && strlen(info->label) > max_len) {
			max_len=strlen(info->label);
		}
	}

	if (!max_len) { return -1; }

	printf("\nROM Info:\n");

	for(info=romInfo; info->attr_type!=END_LIST; info++)
	{
		char *str_data;
		InfoItem *item=info->item;
		if(item->off == 0 || item->len == 0)
		{
			continue;
		}

		if(item->off+item->len >= ih->len)
		{
			printf("%s = INVALID OFFSET/LEN 0x%x/%d\n",info->label, item->off, item->len);
			continue;
		}
		str_data=malloc(item->len+1);
		/* snprintf null terminates for us if string is too long :) */
		snprintf(str_data, item->len+1, "%s", ih->d.s+item->off);	// Leave room for null termination
		printf(" %-*s : '%s'\n", max_len, info->label, str_data);
		free(str_data);
	}
	return 0;
}

static int GetRomDump(const struct ImageHandle *ih, struct section *osconfig)
{
	uint32_t num_of;
	int i, max_len=0;

	if(ih == NULL) return(-1);

	if ((num_of = get_property_value(osconfig, "dumps", "dump_show", NULL))<=0)
	{
		return 0;
	}

	// Find the longest label so we know how big the label column should be
	for(i=1;i<=num_of;i++)
	{
		char label_str[81];
		const char * ptr_label;

		snprintf(label_str,  sizeof(label_str), "dump_%d_label",  i);
		ptr_label   = get_property(       osconfig, "dumps", label_str,   NULL);
		if(ptr_label) {
			if(strlen(ptr_label)>max_len) {
				max_len = strlen(ptr_label);
			}
			ptr_label=NULL;
		}
	}

	printf("\nROM Dumps:\n");

	//
	// Dynamically walks through the config file and shows all properties defined...
	//
	for(i=1;i<=num_of;i++)
	{
		char type_str[81];
		char visible_str[81];
		char label_str[81];
		char offset_str[81];
		char length_str[81];

#ifdef DEBUG_ROM_INFO
		const char * ptr_type;
#endif
		const char * ptr_visible;
		const char * ptr_label;
		uint32_t ptr_offset;
		uint32_t ptr_length;

		snprintf(type_str,   sizeof(type_str), "dump_%d_type",   i);
		snprintf(visible_str,sizeof(visible_str), "dump_%d_visible",i);
		snprintf(label_str,  sizeof(label_str), "dump_%d_label",  i);
		snprintf(offset_str, sizeof(offset_str), "dump_%d_offset", i);
		snprintf(length_str, sizeof(length_str), "dump_%d_len",    i);

		// get config out of ini file...
#ifdef DEBUG_ROM_INFO
		ptr_type    = get_property(       osconfig, "dumps", type_str,    NULL);
#endif
		ptr_visible = get_property(       osconfig, "dumps", visible_str, NULL);
		ptr_label   = get_property(       osconfig, "dumps", label_str,   NULL);
		ptr_offset  = get_property_value( osconfig, "dumps", offset_str,  NULL);
		ptr_length  = get_property_value( osconfig, "dumps", length_str,  NULL);

		if(ptr_length == 0)
		{
			// zero length, skip
		}
		else if(ptr_offset+ptr_length >= ih->len)
		{
			printf("%s = INVALID OFFSET/LEN 0x%x/%d\n",ptr_label, ptr_offset, ptr_length);
		}
		else
		{
			char str_data[1024];
			// restrict maximum dump to 1kbyte [buffer size]
			if(ptr_length > sizeof(str_data) - 1) ptr_length = sizeof(str_data) - 1;	// Leave room for null termination
			DEBUG_ROM("\n%s = %s\n",type_str,    ptr_type);
			DEBUG_ROM("%s = %s\n",visible_str, ptr_visible);
			DEBUG_ROM("%s = '%s'\n",label_str, ptr_label);
			DEBUG_ROM("%s = 0x%x\n",offset_str,  ptr_offset);
			DEBUG_ROM("%s = %d\n",length_str,  ptr_length);

			/* snprintf null terminates for us if string is too long :) */
			snprintf(str_data, sizeof(str_data), "%s", ih->d.s+ptr_offset);
			if(! strcmp("true",ptr_visible))
			{
				printf(" %-*s : '%s'\n", max_len, ptr_label, str_data);
			}
			else
			{
				printf(" %-*s = 'HIDDEN'\n", max_len, ptr_label);
			}
		}
	}
	return 0;
}

/* NEEDLE/HAYSTACK util */
static int FindData(const struct ImageHandle *ih, const char *what,
	const uint8_t *n, const uint8_t *m, int len,	// needle, mask, len of needle/mask
	int off_l, int off_h,							// where to find hi/lo (short word offset into find array)
	uint32_t *offset, size_t offset_len,			// array to store discovered offsets, len of array
	uint32_t *where)								// address of match (ONLY if single match), NULL if not needed
{
	/* Note that off_l and off_h are SHORT WORD offsets, i.e. 1 == 2 bytes */

	int i, found=0;
	uint32_t last_where=0;

	assert((len&1)==0); // make sure its even

	for(i=0;i+len<ih->len;i+=2)
	{
		i=search_image(ih, i, n, m, len, 2);
		if (i<0) break;
		if (i+len<ih->len)
		{
			uint16_t low=le16toh(ih->d.u16[i/2+off_l]);
			uint16_t high=le16toh(ih->d.u16[i/2+off_h]);
			uint32_t addr=(high<<16) | low;

			if (Verbose>1) {
				printf("Found possible %s #%d at 0x%x (from 0x%x)\n",
					what, found+1, addr, i);
			}

			if (addr>Config.base_address && addr-Config.base_address<ih->len) {
				if (Verbose>2) {
					hexdump(ih->d.u8+i-4, 4, " [");
					hexdump(ih->d.u8+i, len, "] ");
					hexdump(ih->d.u8+i+1, 4, "\n");
				}

				if(found<offset_len)
				{
					offset[found]=addr-Config.base_address;
					last_where = i;
				}
				found++;
			}
		}
	}
	if (found==1 && where) *where=last_where;
	return found;
}

//
// Calculate the Bosch Motronic ME71 checksum for the given range
//
static uint32_t CalcChecksumBlk8(const struct ImageHandle *ih, const struct Range *r)
{
	uint32_t	nChecksum = 0, nIndex;

	for(nIndex = r->start; nIndex <= r->end; nIndex++)
	{
		nChecksum+=le16toh(ih->d.u8[nIndex]);
	}

	return nChecksum;
}

static uint32_t CalcChecksumBlk16(const struct ImageHandle *ih, const struct Range *r)
{
	uint32_t	nChecksum = 0, nIndex;

	for(nIndex = r->start/2; nIndex <= r->end/2; nIndex++)
	{
		nChecksum+=le16toh(ih->d.u16[nIndex]);
	}

	return nChecksum;
}

static int NormalizeRange(const struct ImageHandle *ih, struct Range *r)
{
	// special case: leave end markers alone
	if (r->start==0xffffffff && r->end==0xffffffff) return 0;

	// We are only reading the ROM. Therefore the start address must be
	// higher than ROMSTART. Ignore addresses lower than this and
	// remove the offset for addresses we're interested in.
	if (r->start < Config.base_address || r->end < Config.base_address)	//ROMSTART)
	{
		// The checksum block is outside our range
		printf(" ERROR: INVALID STARTADDDR/ENDADDR 0x%x/0x%x is less than base address 0x%x\n",
			r->start, r->end, Config.base_address);
		return -1;
	}

	r->start -= Config.base_address;		//ROMSTART;
	r->end   -= Config.base_address;		//ROMSTART;

	if(r->start>r->end)
	{
		// start is after end!
		printf(" ERROR: INVALID STARTADDDR/ENDADDR: 0x%x>0x%x\n", r->start, r->end);
		return -1;
	}

	if(r->start>=ih->len || r->end>=ih->len)
	{
		// The checksum block is outside our range
		printf(" ERROR: INVALID STARTADDDR/ENDADDR: 0x%x/0x%x is past 0x%x\n", r->start, r->end, (int)ih->len);
		return -1;
	}

	return 0;
}

/* Actual work */
static int FindRSAOffsets(struct ImageHandle *ih)
{
	int signature=0;
	int modulus=0;
	int exponent=0;
	int i;
	int ret=0;
	uint8_t needle[2][14] = {
/*
21 00 DA 8A 7A A0 08 06 E6 F4
80 00 88 40
E6 F4 94 6A.E6 F5.81 00
88 50
88 40 E6 FC BA 4E E6 FD
*/
	    //                                     LL    LL                HH    HH
		{0x80, 0x00, 0x88, 0x40, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x80, 0x00, 0x88, 0x50},
/*
E6 FE 21 00 DA 8A 7A A0 08 06
E0 44 88 40
E6 F4 14 6B E6 F5 81 00
88 50
88 40 E6 FC B2 4D E6 FD
*/
		{0xE0, 0x44, 0x88, 0x40, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x80, 0x00, 0x88, 0x50}
	};
	uint8_t   mask[] =
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff};


	for(i=0;i<2;i++) {
		int found;
		uint32_t offset[2]={0,0};
		uint32_t where=0;

		printf(" Searching for RSA offset #%d...", i);
		found=FindData(ih, "RSA offset", needle[i], mask, sizeof(needle[i]), 3, 5, offset, 2, &where);

		if (found==(i?1:2))
		{
			// crc0 is reserved for pre-region
			DEBUG_RSA(" Found RSA offset #%d 0x%x\n", i, offset[0]);

			if (i==0) {
				DEBUG_RSA(" Found RSA offset #%d 0x%x\n", i, offset[1]);
				signature=offset[0];
				modulus=offset[1];
			} else {
				exponent=offset[0];
			}

			printf("OK\n");
			continue;
		}

		if (found>(i?1:2))
		{
			DEBUG_RSA("%d: Too many matches (%d). RSA find failed\n", i, found);
			continue;
		}

		printf("missing\n");
		ret=-1;
	}

	if (ret) return ret;

	if (signature+RSA_BLOCK_SIZE/8>=ih->len) return -1;
	if (modulus+RSA_BLOCK_SIZE/8>=ih->len) return -1;
	if (exponent+4+RSA_BLOCK_SIZE/8>=ih->len) return -1;

	memcpy(Config.rsa.signature, ih->d.u8+signature, RSA_BLOCK_SIZE/8);
	memcpy(Config.rsa.modulus, ih->d.u8+modulus, RSA_BLOCK_SIZE/8);
	Config.rsa.public_exponent=
		ntohl(*(uint32_t*)(ih->d.u8+exponent));
	memcpy(Config.rsa.default_signature, ih->d.u8+exponent+4, 1024/8);

	printf("         Signature: @%x-%x\n", signature, signature+RSA_BLOCK_SIZE/8);
	if (Verbose>1)
		hexdump(Config.rsa.signature, RSA_BLOCK_SIZE/8, "\n");

	printf("           Modulus: @%x-%x\n", modulus, modulus+RSA_BLOCK_SIZE/8);
	if (Verbose>1)
		hexdump(Config.rsa.modulus, RSA_BLOCK_SIZE/8, "\n");

	printf("          Exponent: @%x = %d\n", exponent,
		Config.rsa.public_exponent);

	if (Verbose>2) {
		printf(" Default Signature @%x-%x\n", exponent+4, exponent+4+RSA_BLOCK_SIZE/8);
		hexdump(Config.rsa.default_signature, RSA_BLOCK_SIZE/8, "\n");
	}

	return 0;
}

static int FindMD5Ranges(struct ImageHandle *ih)
{
	//           r                                         LL    LL
	uint8_t needle[] =
		{0xE1, 0x08, 0xF7, 0xF8, 0xE5, 0xF9, 0xF2, 0xF4, 0x00, 0x00, 0xF2, 0xF5, 0x00, 0x00, 0xF6, 0xF4};
	uint8_t   mask[] =
		{0xff, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff};

	int found=0, i=0;
	int addr=-1;

	printf(" Searching for MD5 ranges...");
	for(i=0;i+sizeof(needle)+2<ih->len;i+=2) {
		i=search_image(ih, i, needle, mask, sizeof(needle), 2);
		if(i<0) break;
		if(i+sizeof(needle)<ih->len) {
			found++;
			DEBUG_RSA(" Found possible MD5 ASM #%d @0x%x\n", found, i);
			addr=i;
		}
	}

	if (found!=1) {
		printf("missing\n");
		return -1;
	} else {
		uint8_t *p = ih->d.u8+addr;
		int count = ((p[1]&0xf0)>>4)+1;
		uint16_t *off = ih->d.u16+(addr/2);
		int table=le16toh(off[4])|0x10000;	/* FIXME: hardcoded HH HH to 0x0081xxxx? */
		DEBUG_RSA(" Found MD5 ASM @0x%x (table=%x, count=%d)\n", addr, table, count);
		if(count>0 && count<=MD5_MAX_BLKS) {
			uint32_t buf[count*2];
			memcpy_from_le32(buf, ih->d.u8+table, sizeof(buf));
			for (i=0;i<count;i++) {
				Config.rsa.md5[i].start = buf[i];	/* first n are start */
				Config.rsa.md5[i].end = buf[i+4];	/* next n are end */
				DEBUG_RSA("0x%08x: 0x%08x-0x%08x\n", table+i,
					Config.rsa.md5[i].start, Config.rsa.md5[i].end);
				NormalizeRange(ih, Config.rsa.md5+i);
			}
		}
	}

	printf("OK\n");
	return 0;
}

static int DoRSA(struct ImageHandle *ih)
{
	public_key kp;
	mpz_t M, DM, C, DC;
	uint8_t buf[RSA_BLOCK_SIZE/8];
	uint8_t dbuf[RSA_BLOCK_SIZE/8];
	uint8_t md5[16];
	uint8_t calc_md5[16];
	MD5_CTX ctx;
	int i;

	memset(md5, 0, sizeof(md5));
	memset(calc_md5, 0, sizeof(calc_md5));

	mpz_init(kp.n);
	mpz_init(kp.e);
	mpz_init(M);
	mpz_init(DM);
	mpz_init(C);
	mpz_init(DC);

	mpz_import(kp.n, RSA_BLOCK_SIZE/8, 1, 1, 0, 0, Config.rsa.modulus);
	mpz_set_ui(kp.e, Config.rsa.public_exponent);
	mpz_import(M, RSA_BLOCK_SIZE/8, 1, 1, 0, 0, Config.rsa.signature);
	mpz_import(DM, RSA_BLOCK_SIZE/8, 1, 1, 0, 0, Config.rsa.default_signature);

	block_encrypt(C, M, kp);
	block_encrypt(DC, DM, kp);

	mpz_export(buf, NULL, 1, 1, 0, 0, C);
	mpz_export(dbuf, NULL, 1, 1, 0, 0, DC);

	for(i=1;i<127 && buf[i]; i++);
	i++;
	if (Verbose>1) {
		printf("signature->MD5: ");
		hexdump(buf+i, 128-i-1, "\n");
	}

	if (128-i-1 == sizeof(md5)) {
		memcpy(md5, buf+i, sizeof(md5));
	}

	for(i=1;i<127 && dbuf[i]; i++);
	i++;
	if (Verbose>2) {
		printf("default signature->MD5: ");
		hexdump(dbuf+i, 128-i-1, "\n");
	}

	ChecksumsFound ++;

	MD5_Init(&ctx);
	for(i=0;i<MD5_MAX_BLKS;i++) {
		int len=Config.rsa.md5[i].end-Config.rsa.md5[i].start+1;
		if (len>0) {
			printf(" %d) Adr: 0x%08X-0x%08X\n", i, Config.rsa.md5[i].start, Config.rsa.md5[i].end);
			MD5_Update(&ctx, ih->d.u8+Config.rsa.md5[i].start, len);
		}
	}

	MD5_Final(calc_md5, &ctx);

	printf(" EncrMD5: ");
	hexdump(md5, 16, "\n");
	printf(" CalcMD5: ");
	hexdump(calc_md5, 16, "");

	if (memcmp(md5, calc_md5, 16)) {
		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			return -1;
		}
		else
		{
			// ErrorsCorrected++;
			ErrorsUncorrectable++;
			printf("  ** UNFIXABLE **\n");
		}
	}
	else
	{
		printf("  OK\n");
	}

	return 0;
}

static int FindROMSYS(struct ImageHandle *ih)
{
	/* autodetect? */
	/* verify stuff is in range? */
	Config.romsys=0x8000;
	return 0;
}

struct ROMSYSDescriptor {
	uint32_t		res00_0F[4];		/* +0x00-0x0F */

	uint32_t		all_param_sum_p;	/* +0x10 */
	uint32_t		res14_1F[3];		/* +0x14-0x1F */

	uint32_t		res20_2F[4];		/* +0x20-0x2F */

	struct Range	all_param;			/* +0x30-0x37 */
	uint32_t		startup_sum;		/* +0x38 */
	uint32_t		program_pages_csum;	/* +0x3C */
};

static int DoROMSYS_Startup(struct ImageHandle *ih, const struct ROMSYSDescriptor *desc)
{
	uint16_t *r16[2];
	uint32_t nCalcStartupSum;

	r16[0]=(uint16_t *)(ih->d.u8 + 0x8000);
	r16[1]=(uint16_t *)(ih->d.u8 + 0xFFFE);
	nCalcStartupSum = le16toh(*r16[0])+le16toh(*r16[1]);

	printf(" Startup section: word[0x00008000]+word[0x0000FFFE]\n");
	printf(" @%x Add=0x%08X CalcAdd=0x%08X",
		Config.romsys + (int)offsetof(struct ROMSYSDescriptor, startup_sum),
		nCalcStartupSum, desc->startup_sum);

	ChecksumsFound ++;

	if (nCalcStartupSum != desc->startup_sum)
	{
		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			return -1;
		}
		else
		{
			uint16_t *p16 = (uint16_t *)(ih->d.u8 + Config.romsys +
				offsetof(struct ROMSYSDescriptor, startup_sum));
			*p16=le16toh(nCalcStartupSum);
			ErrorsCorrected++;
			printf(" ** FIXED **\n");
		}
	}
	else
	{
		printf("  ADD OK\n");
	}

	return 0;
}

static uint32_t ProgramPageSum(struct ImageHandle *ih, const struct Range *r)
{
	uint32_t sum=0;
	int addr;
	for(addr=r->start;addr<r->end;addr+=8*1024) {
		uint16_t *p16[2];
		p16[0]=(uint16_t *)(ih->d.u8+addr);			/* first word of page */
		p16[1]=(uint16_t *)(ih->d.u8+addr+8*1024-2);	/* last word of page */
		if (Verbose>1)
			printf("      word[0x%08X]+word[0x%08X]\n",
				addr, addr+8*1024-2);
		sum+=le16toh(*p16[0]) + le16toh(*p16[1]);
	}
	return sum;
}

static int DoROMSYS_ProgramPages(struct ImageHandle *ih, const struct ROMSYSDescriptor *desc)
{
	uint32_t nCalcProgramPagesSum;
	struct Range r;

	printf(" Program pages: 8k page first+last in 0x0000-0xFFFF and 0x20000-0x%X\n",
		(int)ih->len-1);

	r.start=0x00000; r.end=0x0FFFF;
	nCalcProgramPagesSum=ProgramPageSum(ih, &r);

	r.start=0x20000; r.end=ih->len-1;
	nCalcProgramPagesSum+=ProgramPageSum(ih, &r);

	printf(" @%x Add=0x%08X CalcAdd=0x%08X",
		Config.romsys + (int)offsetof(struct ROMSYSDescriptor, program_pages_csum),
		nCalcProgramPagesSum, desc->program_pages_csum);

	ChecksumsFound ++;

	if (nCalcProgramPagesSum != desc->program_pages_csum)
	{
		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			return -1;
		}
		else
		{
			uint32_t *p32 = (uint32_t *)(ih->d.u8 + Config.romsys +
				offsetof(struct ROMSYSDescriptor, program_pages_csum));
			*p32=le32toh(nCalcProgramPagesSum);
			ErrorsCorrected++;
			printf(" ** FIXED **\n");
		}
	}
	else
	{
		printf("  ADD OK\n");
	}

	return 0;
}

static int DoROMSYS_ParamPage(struct ImageHandle *ih, struct ROMSYSDescriptor *desc)
{
	uint16_t *r16[2];
	uint32_t *p32;
	uint32_t nAllParamSum, nCalcAllParamSum;

	if(desc->all_param_sum_p<Config.base_address ||
		desc->all_param_sum_p-Config.base_address>=ih->len) {
		printf(" ERROR: INVALID ADDR 0x%x\n", desc->all_param_sum_p);
		return -1;
	}

	p32 = (uint32_t *)(ih->d.u8 + desc->all_param_sum_p-Config.base_address);
	nAllParamSum=le32toh(*p32);

	NormalizeRange(ih, &desc->all_param);
	r16[0]=(uint16_t *)(ih->d.u8 + desc->all_param.start);
	r16[1]=(uint16_t *)(ih->d.u8 + desc->all_param.end);
	nCalcAllParamSum = le16toh(*r16[0])+le16toh(*r16[1]);

	printf(" All param page: word[0x%08X]+word[0x%08X]\n",
		desc->all_param.start, desc->all_param.end);
	printf(" @%x Add=0x%04X CalcAdd=0x%04X",
		desc->all_param_sum_p-Config.base_address,
		nAllParamSum, nCalcAllParamSum);

	ChecksumsFound ++;

	if (nCalcAllParamSum != nAllParamSum)
	{
		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			return -1;
		}
		else
		{
			*p32=le32toh(nCalcAllParamSum);
			ErrorsCorrected++;
			printf(" ** FIXED **\n");
		}
	}
	else
	{
		printf("  ADD OK\n");
	}

	return 0;
}

static int DoROMSYS(struct ImageHandle *ih)
{
	struct ROMSYSDescriptor desc;
	int result = 0;

	memcpy_from_le32(&desc, ih->d.u8+Config.romsys, sizeof(desc));

	DEBUG_ROMSYS("00 0x%08X 0x%08X 0x%08X 0x%08X\n",
		desc.res00_0F[0], desc.res00_0F[1],
		desc.res00_0F[2], desc.res00_0F[3]);

	DEBUG_ROMSYS("allparam csum @0x%08X\n", desc.all_param_sum_p);

	DEBUG_ROMSYS("14 0x%08X 0x%08X 0x%08X\n",
		desc.res14_1F[0], desc.res14_1F[1],
		desc.res14_1F[2]);

	DEBUG_ROMSYS("20 0x%08X 0x%08X 0x%08X 0x%08X\n",
		desc.res20_2F[0], desc.res20_2F[1],
		desc.res20_2F[2], desc.res20_2F[3]);

	DEBUG_ROMSYS("allparam first/last: 0x%08X, 0x%08X\n",
		desc.all_param.start, desc.all_param.end);

	DEBUG_ROMSYS("startup_sum 0x%08X\n", desc.startup_sum);

	DEBUG_ROMSYS("program_pages_csum 0x%08X\n", desc.program_pages_csum);

	result |= DoROMSYS_Startup(ih, &desc);
	result |= DoROMSYS_ProgramPages(ih, &desc);
	result |= DoROMSYS_ParamPage(ih, &desc);

	return result;
}

static int FindMainCRCPreBlk(const struct ImageHandle *ih)
{
	int found;
	uint32_t offset=0;
	uint32_t where=0;
	//                                LL    LL                HH    HH          s
	uint8_t needle[] = {0xE6, 0xFC, 0x00, 0x00, 0xE6, 0xFD, 0x80, 0x00, 0xE0, 0x0E, 0xDA, 0x00, 0x00, 0x00, 0xF6, 0xF4};
	uint8_t   mask[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff, 0xff, 0x0f, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff};

	printf(" Searching for main data CRC pre block...");
	DEBUG_FLUSH_CRC;

	found=FindData(ih, "CRC pre block", needle, mask, sizeof(needle), 1, 3, &offset, 1, &where);

	if (found==1)
	{
		// crc0 is reserved for pre-region
		Config.crc[0].r.start=offset;
		Config.crc[0].r.end=offset+(ih->d.u8[where+9]>>4)-1;	// s
		DEBUG_CRC("Found %s #%d 0x%x-0x%x (0x%x): ", "CRC pre block", 0, offset, Config.crc[0].r.end, where);

		printf("OK\n");
		return 0;
	}

	if (found>1)
	{
		DEBUG_CRC("Too many matches (%d). CRC/csum block start find failed\n", found);
	}

	printf("missing\n");
	return 0;
}

static int FindMainCRCBlks(const struct ImageHandle *ih)
{
	int i, found, ret0=-1, ret1=-1;
	uint32_t offset[MAX_CRC_BLKS];
	//                            LL    LL                HH    HH
	uint8_t n0[] = {0xE6, 0xF8, 0x00, 0x00, 0xE6, 0xF9, 0x80, 0x00, 0xF2, 0xF4 /*, 0x00, 0x00, 0x24, 0x8F */};
	uint8_t m0[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff /*, 0x00, 0x00, 0xff, 0xff */};
	//                                        LL    LL                HH    HH
	uint8_t n1[] = {0x10, 0x9B, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x80, 0x00 /*, 0x26, 0xF4, 0x9B, 0xE6 */};
	uint8_t m1[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff /*, 0xff, 0xff, 0xff, 0xff */};

	printf(" Searching for main data CRC/csum blocks...");
	DEBUG_FLUSH_CRC;

	found=FindData(ih, "CRC/csum block starts", n0, m0, sizeof(n0), 1, 3, offset, MAX_CRC_BLKS, NULL);

	if (found>0 && found<=MAX_CRC_BLKS)
	{
		for (i=0;i<found;i++)
		{
			DEBUG_CRC("Found %s #%d at 0x%x\n", "CRC/csum block start", i+1, offset[i]);
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].r.start=offset[i];
			ret0=0;
		}
	}

	if (!found)
	{
		DEBUG_CRC("CRC/csum block start find failed\n");
	}
	else if (found>MAX_CRC_BLKS)
	{
		DEBUG_CRC("Too many matches (%d). CRC/csum block start find failed\n", found);
	}

	found=FindData(ih, "CRC/csum block end", n1, m1, sizeof(n1), 2, 4, offset, MAX_CRC_BLKS, NULL);

	if (found>0 && found<=MAX_CRC_BLKS)
	{
		for (i=0;i<found;i++)
		{
			DEBUG_CRC("Found %s #%d at 0x%x\n", "CRC/csum block end", i+1, offset[i]);
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].r.end=offset[i];
			ret1=0;
		}
	}

	if (!found)
	{
		DEBUG_CRC("CRC/csum block end find failed\n");
	}
	else if (found>MAX_CRC_BLKS)
	{
		DEBUG_CRC("Too many matches (%d). CRC/csum block end find failed\n", found);
	}

	if (ret0||ret1)
	{
		if (ih->len==512*1024 || ih->pad == PADDING_TRY_512K_CRC)
		{
			printf("missing\n");
			printf(" Falling back to default 512k CRC blocks...");
			Config.crc[1].r.start=0x10000;
			Config.crc[1].r.end=0x13fff;
			Config.crc[2].r.start=0x14300;
			Config.crc[2].r.end=0x17f67;
			Config.crc[3].r.start=0x18191;
			Config.crc[3].r.end=0x1fbff;
			ret0=ret1=0;
		}
	}

	printf("%s\n", (ret0||ret1)?"FAIL":"OK");
	return ret0||ret1;
}

#ifdef DEBUG_CRC_MATCHING
#define MAX_CRC_OFFSETS 10
#else
#define MAX_CRC_OFFSETS MAX_CRC_BLKS
#endif
static int FindMainCRCOffsets(const struct ImageHandle *ih)
{
	int i, found;
	uint32_t offset[MAX_CRC_OFFSETS];
	//                                                        LL    LL                HH    HH
	uint8_t needle[] = {0xF6, 0xF5, 0x00, 0x00, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x80, 0x00, 0xDA, 0x00 /*, 0x00, 0x00, 0xe6, 0x00, 0x04, 0x02 */};
	uint8_t   mask[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff /*, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff */};

	printf(" Searching for main data CRC offsets...");
	DEBUG_FLUSH_CRC;

	found=FindData(ih, "CRC offset", needle, mask, sizeof(needle), 3, 5, offset, MAX_CRC_OFFSETS, NULL);

	if (found>0 && found<=MAX_CRC_OFFSETS)
	{
		for (i=0;i<found;i++)
		{
			DEBUG_CRC("Found CRC offset #%d at 0x%x\n", i+1, offset[i]);
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].offset=offset[i];
		}
	}

	if (found!=3)
	{
		DEBUG_CRC("Did not find exactly 3 matches (got %d). CRC offset find failed\n", found);
		for(i=1;i<MAX_CRC_BLKS;i++) {
			Config.crc[i].offset=0;
		}
		printf("missing\n");
		return -1;
	}

	/* if we found exactly 3 crc values, and region 4 exists, use region 3's crc for calcing 3+4 */
	if (Config.crc[4].r.start && Config.crc[4].r.end)
	{
		Config.crc[4].offset=Config.crc[3].offset;
		Config.crc[3].offset=0;
	}

	printf("OK\n");
	return 0;
}

static int FindMainCSMOffsets(const struct ImageHandle *ih)
{
	int found;
	uint32_t offset;
	//                                            LL    LL                HH    HH
	uint8_t needle[] = {0xE1, 0x0C, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x80, 0x00, 0xDA, 0x00 /*, 0xf0, 0xe1, 0x0c, 0xe6 */};
	uint8_t   mask[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xf0, 0xff, 0xff, 0xff /*, 0xf0, 0xff, 0xff, 0xff */};

	printf(" Searching for main data checksum offsets...");
	DEBUG_FLUSH_CRC;

	found=FindData(ih, "Checksum offset", needle, mask, sizeof(needle), 2, 4, &offset, 1, NULL);

	if (found!=1) {
		DEBUG_CRC("Did not find exactly 1 match (got %d). Checksum offset find failed\n", found);
		Config.csm_offset=0;
		printf("FAIL\n");
		return -1;
	}

	DEBUG_CRC("Found checksum offset at 0x%x\n", offset);
	Config.csm_offset=offset;
	printf("OK\n");
	return 0;
}

static int DoMainCRCs(struct ImageHandle *ih)
{
	int result=0;
	int i;
	uint32_t nCalcCRCSeed = 0;

	for (i=0; i<5; i++)
	{
		if(Config.crc[i].r.start && Config.crc[i].r.end)
		{
			uint32_t nStart = Config.crc[i].r.start;
			size_t nLen = Config.crc[i].r.end - Config.crc[i].r.start + 1;
			uint32_t nCRCAddr = Config.crc[i].offset;
			uint32_t nCRC;
			uint32_t nCalcCRC;
			uint32_t *p32;

			nCalcCRC = crc32(nCalcCRCSeed, ih->d.u8+nStart, nLen);

			printf(" %d) Adr: 0x%06X-0x%06X", i, Config.crc[i].r.start, Config.crc[i].r.end);

			if (nCRCAddr+4>ih->len)
			{
				printf(" @%05x INVALID ADDRESS\n", nCRCAddr);
			}
			else if (nCRCAddr)
			{
				/* possibly unaligned, so we cant do tricks wtih ih->d.u32 */
				p32=(uint32_t *)(ih->d.u8 + nCRCAddr);
				nCRC=le32toh(*p32);

				printf(" @%05x CRC: %08X CalcCRC: %08X%s", nCRCAddr, nCRC, nCalcCRC, nCalcCRCSeed?"(r)":"   ");
				ChecksumsFound ++;

				if (nCalcCRC != nCRC)
				{
					ErrorsFound++;
					if (Config.readonly)
					{
						printf("  ** NOT OK **\n");
						result|=-1;
					}
					else
					{
						*p32=le32toh(nCalcCRC);
						ErrorsCorrected++;
						printf(" ** FIXED **\n");
					}
				}
				else
				{
					printf("  CRC OK\n");
				}
			} else {
				printf("                      CalcCRC: %08X%s\n", nCalcCRC, nCalcCRCSeed?"(r)":"   ");
			}

			if (Config.crc[0].r.start && Config.crc[0].r.end)
				nCalcCRCSeed=nCalcCRC;
		}
		else
		{
			DEBUG_CRC(" %d) Adr: 0x%06X-0x%06X SKIPPED\n", i,
				Config.crc[0].r.start, Config.crc[0].r.end);
		}
	}
	return result;
}

static int DoMainCSMs(struct ImageHandle *ih)
{
	int result=0;
	int i;
	uint32_t nCalcCSM = 0;
	uint32_t nCSMAddr = Config.csm_offset;
	uint32_t *p32;
	uint32_t nCSM, nCSMinv;

	if (nCSMAddr+4>ih->len)
	{
		printf(" @%05x INVALID ADDRESS\n", nCSMAddr);
		return -1;
	}

	/* possibly unaligned, so we cant do tricks wtih ih->d.u32 */
	p32 =(uint32_t *)(ih->d.u8 + nCSMAddr);
	nCSM = le32toh(p32[0]);
	nCSMinv = le32toh(p32[1]);

	for (i=1; i<5; i++)
	{
		if(Config.crc[i].r.start && Config.crc[i].r.end)
		{
			printf(" %d) Adr: 0x%06X-0x%06X", i,
				Config.crc[i].r.start, Config.crc[i].r.end);

			/* bytewise checksum */
			nCalcCSM += CalcChecksumBlk8(ih, &Config.crc[i].r);

			printf(" CalcCSM: %08X\n", nCalcCSM);
		}
	}

	printf(" @%05x CSM: %08X CalcCSM: %08X", nCSMAddr, nCSM, nCalcCSM);
	ChecksumsFound ++;

	if (nCalcCSM != nCSM)
	{
		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			result|=-1;
		}
		else
		{
			p32[0]=le32toh(nCalcCSM);
			p32[1]=le32toh(~nCalcCSM);
			ErrorsCorrected++;
			printf(" ** FIXED **\n");
		}
	} else if (nCSM != ~nCSMinv) {
		printf(" @%05x CSM: %08X CSMinv: %08X (%08X)", nCSMAddr, nCSM, nCSMinv, ~nCSMinv);

		ErrorsFound++;
		if (Config.readonly)
		{
			printf("  ** NOT OK **\n");
			result|=-1;
		}
		else
		{
			p32[1]=le32toh(~nCSM);
			ErrorsCorrected++;
			printf(" ** FIXED **\n");
		}
	}

	else
	{
		printf("  Main data checksum OK\n");
	}
	return result;
}

static int FindMainProgramOffset(const struct ImageHandle *ih)
{
	int i, found=0, offset=0;
	uint32_t needle[4];
	uint32_t mask[4];

	printf(" Searching for main program checksum..");
	DEBUG_FLUSH_MAIN;

	needle[0]=htole32(Config.base_address);			/* 0x000000 */
	needle[1]=htole32(Config.base_address+0x0fbff);	/* 0x00fbff */
	needle[2]=htole32(Config.base_address+0x20000);	/* 0x020000 */
	needle[3]=htole32(Config.base_address+0xf00ff);	/* 0x07ffff 512k flash
													   0x0febff oddball?
													   0x0fffff 1M flash */
	mask[0]=htole32(0xffffffff);
	mask[1]=htole32(0xffffffff);
	mask[2]=htole32(0xffffffff);
	mask[3]=htole32(0xfff700ff);

	for(i=0;i+sizeof(needle)<ih->len;i+=2)
	{
		i=search_image(ih, i, needle, mask, sizeof(needle), 2);
		if (i<0) break;
		if (i+sizeof(needle)<ih->len)
		{
			DEBUG_MAIN("Found possible main block descriptor at 0x%x\n", i);
			offset=i;
			found++;
		}
	}

	if (found==1)
	{
		DEBUG_MAIN("Found main block descriptor at 0x%x\n", offset);
		Config.main_checksum_offset=offset;
		printf("OK\n");
		return 0;
	}
	else if (found>1)
	{
		DEBUG_MAIN("Found %d main block descriptor matches\n", found);
	}

	printf("FAIL\n");
	return -1;
}

static int FindMainProgramFinal(const struct ImageHandle *ih)
{
	int offset=ih->len-0x20;
	struct ChecksumPair *csum = (struct ChecksumPair *)(ih->d.u8+offset);

	if (csum->v == ~csum->iv)
	{
		DEBUG_MAIN("Found main csum at 0x%x\n", offset);
		Config.main_checksum_final=offset;
		return 0;
	}

	return -1;
}

//
// Reads the main checksum for the whole ROM
//
static int DoMainChecksum(struct ImageHandle *ih, uint32_t nOffset, uint32_t nCsumAddr)
{
	int errors=0;
	struct Range r[2];
	struct ChecksumPair csum;
	uint32_t nCalcChksum;
	uint32_t nCalcChksum2;

	printf(" ROM Checksum Block Offset Table @%05x [16 bytes]:\n",
		Config.main_checksum_offset);

	// C16x processors are little endian
	// copy from (le) buffer into our descriptor
	memcpy_from_le32(r, ih->d.u8+nOffset, sizeof(r));

	if (NormalizeRange(ih, r) || NormalizeRange(ih, r+1) ||
	    r[0].start==0xffffffff || r[1].start==0xffffffff)
	{
		printf(" ERROR! BAD MAIN CHECKSUM DESCRIPTOR(s)\n");
		ErrorsUncorrectable++;
		return -1;
	}

	// block 1
	nCalcChksum = CalcChecksumBlk16(ih, &r[0]);
	printf(" 1) Adr: 0x%06X-0x%06X\n", r[0].start, r[0].end);

	if (r[0].end + 1 != r[1].start)
	{
		struct Range sr;
		uint32_t ss, sc;
		sr.start = r[0].end+1;
		sr.end = r[1].start-1;
		//struct Range sr = {.start = 0x10000, .end = 0x1FFFF};
	    ss = CalcChecksumBlk16(ih, &sr);
		sc = crc32(0, ih->d.u8+sr.start, sr.end-sr.start+1);
		printf("         0x%06X-0x%06X  SKIPPED CalcChk: 0x%08X CalcChk: 0x%08X\n",
			sr.start, sr.end, ss, sc);
	}

	// block 2
	nCalcChksum2= CalcChecksumBlk16(ih, &r[1]);
	printf(" 2) Adr: 0x%06X-0x%06X\n", r[1].start, r[1].end);

	nCalcChksum += nCalcChksum2;

	// C16x processors are little endian
	// copy from (le) buffer
	memcpy_from_le32(&csum, ih->d.u8+nCsumAddr, sizeof(csum));

	printf(" @%05x Chksum: 0x%08X", Config.main_checksum_final, csum.v);
	if(csum.v != ~csum.iv)
	{
		printf(" ~Chksum: 0x%08X INV NOT OK", csum.iv);
		errors++;
	}

	printf(" CalcChk: 0x%08X", nCalcChksum);
	ChecksumsFound ++;
	if(csum.v != nCalcChksum) { errors++; }

	if(!errors)
	{
		printf("  Main program checksum OK\n");
		return 0;
	}

	ErrorsFound+=errors;

	if(Config.readonly)
	{
		printf(" ** NOT OK **\n");
		return -1;
	}

	csum.v = nCalcChksum;
	csum.iv = ~nCalcChksum;

	memcpy_to_le32(ih->d.u8+nCsumAddr, &csum, sizeof(csum));

	printf(" ** FIXED **\n");
	ErrorsCorrected+=errors;
	return 0;
}

/* which=0: MP block #1 */
/* which=1: MP block #2 */
static int FindChecksumBlks(const struct ImageHandle *ih, int which)
{
	int i, found=0, offset=0;
	uint32_t needle[2];
	int size=0;

	printf(" Searching for multipoint block descriptor #%d...",
		which+1);
	DEBUG_FLUSH_MULTIPOINT;

	if (which==0) {
		needle[0]=htole32(Config.base_address+0x24000);
		/* actually, mp #1 isn't allowed to match this,
		   its in mp #2 */
		needle[1]=htole32(Config.base_address+0x27fff);
		size=4;
	} else {
#ifdef CHECK_BOOTROM_MP
		needle[0]=htole32(0);
		needle[1]=htole32(0x3fff);
#else
		needle[0]=htole32(Config.base_address);
		needle[1]=htole32(Config.base_address+0x3fff);
#endif
		size=8;
	}

	for(i=0x10000;i+Config.multipoint_desc_len<ih->len;i+=2)
	{
		DEBUG_MULTIPOINT("%d: Searching starting at 0x%d\n", which+1, i);
		i=search_image(ih, i, needle, NULL, size, 2);
		if (i<0) break;

		if (i+Config.multipoint_desc_len<ih->len)
		{
			struct MultipointDescriptor *desc =
				(struct MultipointDescriptor *)(ih->d.u8+i);

			/* for mp block 1, don't be picky about inv */
			if ((which==0) || desc->csum.v==~desc->csum.iv)
			{
				/* make sure we don't match the mp #2 when looking for #1 */
				if(which || desc->r.end != needle[1]) {
					DEBUG_MULTIPOINT("%d: Found possible multipoint descriptor #%d at 0x%x\n",
						which+1, found+1, i);
					DEBUG_MULTIPOINT("0x%x-0x%x\n", desc->r.start, desc->r.end);
					offset=i;
					found++;
				}
			}
		}
	}

	if (found==1)
	{
		/* test next block to make sure it looks reasonable */
		struct MultipointDescriptor *desc =
			(struct MultipointDescriptor *)(ih->d.u8+offset+Config.multipoint_desc_len);

		/* for mp block 1, don't be picky about inv */
		if ((which==0) || desc->csum.v==~desc->csum.iv)
		{
			DEBUG_MULTIPOINT("Found descriptor #%d at 0x%x\n", which+1,
				offset);
			Config.multipoint_block_start[which]=offset;
			printf("OK\n");
			return 0;
		}
	}

	printf(which==0?"missing\n":"FAIL\n");
	return -1;
}

// Reads the individual checksum blocks that start at nStartBlk
// -2 for ignored bootrom block
// -1 for error
//  0 for no error
//  1 for last block
static int DoChecksumBlk(struct ImageHandle *ih, uint32_t nStartBlk, struct strbuf *buf, int bootrom)
{
	// read the ROM byte by byte to make this code endian independant
	// C16x processors are little endian
	struct MultipointDescriptor desc;
	struct MultipointDescriptor *pDesc;
	uint32_t nCalcChksum;
	int errors=0;

	sbprintf(buf, "<%x> ",nStartBlk);

	if(nStartBlk + sizeof(desc) >= ih->len)
	{
		sbprintf(buf, " ERROR! INVALID STARTBLK/LEN 0x%x/%ld ** NOT OK **\n", nStartBlk, (long int)ih->len);
		ErrorsUncorrectable++;
		return -1;	// Uncorrectable Error
	}

	// C16x processors are little endian
	// copy from (le) buffer into our descriptor
	memcpy_from_le32(&desc, ih->d.u8+nStartBlk, sizeof(desc));

	if (!bootrom) {
		if (NormalizeRange(ih, &desc.r))
		{
			ErrorsUncorrectable++;
			return -1;
		}
	}

	sbprintf(buf, " Adr: 0x%06X-0x%06X ", desc.r.start, desc.r.end);

	if(desc.r.start==0xffffffff)
	{
		sbprintf(buf, " END\n");
		return 1;	// end of blks
	}

	sbprintf(buf, "Chk: 0x%08X", desc.csum.v);

	if(desc.csum.v != ~desc.csum.iv)
	{
		sbprintf(buf, "  ~0x%08X INV NOT OK", desc.csum.iv);
		errors++;
	}

	if (bootrom && ih->bootrom_whitelist) {
		/* whitelisted */
		nCalcChksum = desc.csum.v;
		sbprintf(buf, " Boot: (whitelisted)");
	} else {
		// calc checksum
		nCalcChksum = CalcChecksumBlk16(ih, &desc.r);

		sbprintf(buf, " CalcChk: 0x%08X", nCalcChksum);
		ChecksumsFound ++;

		if (desc.csum.v != nCalcChksum) {
			errors++;
		}
	}

	if (!errors)
	{
		sbprintf(buf, " OK\n");
		return bootrom?-2:0;
	}

	ErrorsFound+=errors;

	if (Config.readonly)
	{
		sbprintf(buf, " ** NOT OK **\n");
		return -1;
	}

	desc.csum.v = nCalcChksum;
	desc.csum.iv = ~nCalcChksum;
	pDesc=(struct MultipointDescriptor *)(ih->d.u8+nStartBlk);
	memcpy_to_le32(&pDesc->csum, &desc.csum, sizeof(desc.csum));

	sbprintf(buf, " ** FIXED **\n");
	ErrorsCorrected+=errors;
	return 0;
}

// vim:ts=4:sw=4
