/* me7sum [ firmware management tool for Bosch ME7.x firmware]
   By 360trev

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
#include <stdint.h>
#include <errno.h>

#include "inifile_prop.h"

// defines
#define FSEEK(a,b,c) { \
	if(fseek(a,b,c)) { \
		fprintf(stderr,"Line %d: fseek %x: %s\n", __LINE__, b, strerror(errno)); \
		exit(-1); \
	} \
};

#define FREAD(a,b,c,d) { \
	if(fread(a,b,c,d)<=0) { \
		fprintf(stderr,"Line %d: fread: %s\n", __LINE__, feof(d)?"EOF":ferror(d)?"ERR":"???"); \
		exit(-1); \
	} \
};


// structures
struct Range {
	uint32_t	start;
	uint32_t	end;
};

struct ChecksumPair {
	uint32_t	v;	// value
	uint32_t	iv;	// inverse value
};

// descriptors
struct MultipointDescriptor {
	struct Range			r;
	struct ChecksumPair	csum;
};

struct MainDescriptor {
	struct Range r[2];
};


// main firmware checksum validation
struct rom_config {
	uint32_t  base_address;				/* rom base address */
	uint32_t  multipoint_block_start;	/* start of multipoint block descriptors */
	uint32_t  multipoint_block_len;		/* size of descriptors */
	uint32_t  main_checksum_offset;		/* two start/end pairs, one at offset, other at offset+8 */
	uint32_t  main_checksum_final;		/* two 4 byte checksum (one inv) for two blocks conctatenated above) */
} Config;

// boot sector validation (optional, generally already in multipoint blocks above) */
struct rom_boot_config {
	struct Range	addr;
	uint32_t		checksum;
} BootConfig;

//
// List of configurable properties to read from config file into our programme...
// [this stops us having to hardcode values into the code itself]
//
PropertyListItem romProps[] = {
	// get rom region information
	{	GET_VALUE,  &Config.base_address,			"ignition", "rom_firmware_start",		},
	{	GET_VALUE,  &Config.multipoint_block_start,	"ignition", "rom_checksum_block_start",	},
	{	GET_VALUE,  &Config.multipoint_block_len,	"ignition", "rom_checksum_block_len",	},
	{	GET_VALUE,  &Config.main_checksum_offset,	"ignition", "rom_checksum_offset",		},
	{	GET_VALUE,  &Config.main_checksum_final,	"ignition", "rom_checksum_final",		},
	// get boot sector validation information
	{	GET_VALUE,  &BootConfig.addr.start,			"ignition", "rom_boot_Startaddr",		},
	{	GET_VALUE,  &BootConfig.addr.end,			"ignition", "rom_boot_Endaddr",			},
	{	GET_VALUE,  &BootConfig.checksum,			"ignition", "rom_boot_Chksum",			},
	{ END_LIST,   0, "",""},
};

static int GetRomInfo(FILE *fh, struct section *osconfig);
static uint32_t CalcChecksumBlk(FILE *fh, const struct Range *);
static uint32_t ReadChecksumBlks(FILE *fh, uint32_t nStartBlk);
static void ReadMainChecksum(FILE *fh);

/*
 * main()
 *
 */

int main(int argc, char **argv)
{
	int	iTemp;
	int result;
	uint32_t chksum;
	FILE *fh;
	struct section *osconfig;

	// information about the tool
	printf("ME7Tool [ Management tool for Bosch ME7.x firmwares]\n");
	printf("Inspiration from Andy Whittaker's tools and information\n");
	printf("Written by 360trev [FREEWARE]. \n\n");

	if(argc < 3) {
		printf("Usage: %s <firmware.bin> <config.ini>\n",argv[0]);
		return -1;
	}

	printf("Attemping to open firmware config file %s\n",argv[2]);
	// load properties file into memory
	osconfig = read_properties(argv[2]);
	if(osconfig != NULL)
	{
		// get rom region information from config file (see defined property list)
		result = process_properties_list(osconfig, romProps);

		// open the firmware file
		printf("\nAttemping to open firmware file %s\n",argv[1]);
		if((fh = fopen(argv[1],"rb")) != 0)
		{
			//
			// Step #0 Show interesting ROM information
			//
			printf("\nShowing ROM info (typically ECUID Table)\n\n");
			result = GetRomInfo(fh, osconfig);

			//
			// Step #1 Verify Boot checksums (if requested)
			//
			if(BootConfig.addr.start && BootConfig.addr.end) {
				printf("\nReading Boot checksum...\n");
				chksum = CalcChecksumBlk(fh, &BootConfig.addr);
				printf("Start: 0x%04X  End: 0x%04X  Chksum: 0x%08X  CalcChk: 0x%08X", BootConfig.addr.start,  BootConfig.addr.end, BootConfig.checksum, chksum);
				if(chksum == BootConfig.checksum) {
					printf("       OK     \n");
				}	else {
					printf("  ** NOT OK **\n");
				}
			}

			//
			// Step #2 Multi point checksums
			//
			printf("\nReading Multipoint Checksum Block...\n");
			for(iTemp=0; iTemp<64; iTemp++)
			{
				printf("%2d) ",iTemp+1);
				result = ReadChecksumBlks(fh, Config.multipoint_block_start+(Config.multipoint_block_len*iTemp));
				if (result == 1) {
					result = 0;
					break;	// end of blocks;
				}
				// if(result != 0) { break; }		// stop on first checksum that failed...
			}
			if(result == 0)			// if checksum failed abort or carry on
			{
				printf("[%d x <16> = %d bytes]\n", iTemp, iTemp*16);
				//
				// Step #3 Main ROM checksums
				//
				printf("\nReading main ROM checksum...\n");
				ReadMainChecksum(fh);
			}
			else
			{
				printf("Stopped.\n");
			}
			// close the file
			if(fh != 0) fclose(fh);
		}
		else
		{
			printf("failed to open firmware file\n");
		}

		// free config
		if(osconfig != 0) {
			// freeing properties file..
			free_properties(osconfig);
		}
	}
	else
	{
		printf("failed to open config file\n");
	}
	return 0;
}

/*
 * GetRomInfo
 *
 * - uses config file to parse rom data and show interesting information about this rom dump
 */

static int GetRomInfo(FILE *fh, struct section *osconfig)
{
	char str_data[1024];
	char type_str[256];
	char visible_str[256];
	char label_str[256];
	char offset_str[256];
	char length_str[256];
	uint32_t num_of;
#ifdef DEBUG
	char * ptr_type;
#endif
	char * ptr_visible;
	char * ptr_label;
	uint32_t ptr_offset;
	uint32_t ptr_length;
	int i;

	if(fh == 0) return(-1);
	//
	// Step #0 this dynamically walks through the config file and shows all properties defined...
	//
	num_of = get_property_value(osconfig, "dumps", "dump_show", NULL);
	for(i=1;i<=num_of;i++)
	{
		sprintf(type_str,   "dump_%d_type",   i);
		sprintf(visible_str,"dump_%d_visible",i);
		sprintf(label_str,  "dump_%d_label",  i);
		sprintf(offset_str, "dump_%d_offset", i);
		sprintf(length_str, "dump_%d_len",    i);

		// get config out of ini file...
#ifdef DEBUG
		ptr_type    = get_property(       osconfig, "dumps", type_str,    NULL);
#endif
		ptr_visible = get_property(       osconfig, "dumps", visible_str, NULL);
		ptr_label   = get_property(       osconfig, "dumps", label_str,   NULL);
		ptr_offset  = get_property_value( osconfig, "dumps", offset_str,  NULL);
		ptr_length  = get_property_value( osconfig, "dumps", length_str,  NULL);

		if(ptr_length == 0)
		{
			// no length to source. skip it...
		}
		else
		{
			// restrict maximum dump to 1kbyte [buffer size]
			if(ptr_length > 1024) ptr_length = 1024;
#ifdef DEBUG
			printf("\n%s = %s\n",type_str,    ptr_type);
			printf("%s = %s\n",visible_str, ptr_visible);
			printf("%s = '%s'\n",label_str, ptr_label);
			printf("%s = %p\n",offset_str,  ptr_offset);
			printf("%s = %p\n",length_str,  ptr_length);
#endif
			// seek to correct file offset
			FSEEK(fh, ptr_offset,  SEEK_SET);
			// read the data from file into buffer
			FREAD(str_data, ptr_length, 1, fh);
			// null terminate buffer
			str_data[ptr_length]  = 0x00;
			if(! strncmp("true",(char *)ptr_visible,4))
			{
				printf("%s = '%s'\n",ptr_label, str_data);
			} else {
				printf("%s = 'HIDDEN'\n",ptr_label);
			}
		}
	}
	return 0;
}


// Reads the individual checksum blocks that start at nStartBlk
static uint32_t ReadChecksumBlks(FILE *fh, uint32_t nStartBlk)
{
	// read the ROM byte by byte to make this code endian independant
	// C16x processors are little endian
	struct MultipointDescriptor desc;
	uint32_t nCalcChksum;
	uint32_t nCalcInvChksum;
	uint32_t result;

	printf("<%x> ",nStartBlk);
	fflush(stdout);
	FSEEK(fh, nStartBlk, SEEK_SET);
	FREAD(&desc, sizeof(desc), 1, fh);
	// todo: endian swap on bigendian host
	printf("Adr: 0x%04X-0x%04X ", desc.r.start, desc.r.end);
	fflush(stdout);

	if(desc.r.start==0xffffffff) {
		printf(" END\n");
		return 1;	// end of blks
	}

	if(desc.r.start>=desc.r.end || desc.csum.v != ~desc.csum.iv) {
		printf(" ** NOT OK **\n");
		return -1;	// Error
	}

	// calc checksum
	nCalcChksum = CalcChecksumBlk(fh, &desc.r);
	// inverted checksum
	nCalcInvChksum = ~nCalcChksum;

	printf("Sum: 0x%08X  ~0x%08X == Calc: 0x%08X ~0x%08X", desc.csum.v, desc.csum.iv, nCalcChksum, nCalcInvChksum);
	fflush(stdout);
	if(desc.csum.v == nCalcChksum)
	{
		if(desc.r.start == 0x810000) {			// this start address contains the maps region
			printf("  OK [MAPS]\n");
		}
		else
		{
			if(desc.csum.v == 0x1fffe000) {			// this value is checksum for all zero's... meaning empty block
				printf("  OK [EMPTY]\n");
			} else {
				printf("  OK [OTHER]\n");
			}
		}
		result = 0;
	}	else {
		printf(" ** NOT OK **\n");
		result = -1;
	}
	return(result);
}

//
// Reads the main checksum for the whole ROM
//
static void ReadMainChecksum(FILE *fh)
{
	struct MainDescriptor desc;
	struct ChecksumPair csum;
	uint32_t nCalcChksum;
	uint32_t nCalcChksum2;

	printf("Seeking to ROM Checksum Block Offset Table 0x%X [16 bytes table]\n\n",Config.main_checksum_offset);

	// read the ROM byte by byte to make this code endian independant
	// C16x processors are little endian
	FSEEK(fh, Config.main_checksum_offset+0, SEEK_SET);
	FREAD(&desc, sizeof(desc), 1, fh);
	// todo: endian swap on bigendian host
	nCalcChksum = CalcChecksumBlk(fh, desc.r);
	printf("Start: 0x%04X  End: 0x%04X  Block #1 - nCalcChksum=0x%04x\n", desc.r[0].start, desc.r[0].end,nCalcChksum);

	printf(" 10000: Start: 0x%04X  End: 0x%04X - MAP REGION SKIPPED, NOT PART OF ROM CHECKSUM\n", 0x810000, 0x81ffff);

	// read in the checksum information, block by block
	nCalcChksum2= CalcChecksumBlk(fh, desc.r+1);
	printf("Start: 0x%04X  End: 0x%04X  Block #2 - nCalcChksum=0x%04x\n", desc.r[1].start, desc.r[1].end,nCalcChksum2);

	nCalcChksum += nCalcChksum2;
	printf("\n\nRead in stored MAIN ROM checksum block @ 0x%X [8 bytes]\n\n",Config.main_checksum_final);

	//Read in the stored checksum --- GOOD
	FSEEK(fh, Config.main_checksum_final, SEEK_SET);
	FREAD(&csum, sizeof(csum), 1, fh);
	// todo: endian swap on bigendian host
	printf("Chksum : 0x%08X ~Chksum : 0x%08X  \nCalcChk: 0x%08X ~CalcChk: 0x%08X", csum.v, csum.iv, nCalcChksum, ~nCalcChksum);
	if(csum.v == ~csum.iv && csum.v == nCalcChksum) {
		printf("  Main ROM OK\n");
	} else {
		printf(" ** NOT OK **\n");
	}
}

//
// Calculate the Bosch Motronic ME71 checksum for the given range
//
static uint32_t CalcChecksumBlk(FILE *fh, const struct Range *r)
{
	uint32_t	nStartAddr=r->start;
	uint32_t	nEndAddr=r->end;
	uint32_t	nChecksum = 0, nIndex, nTemp;
	uint8_t p[2];

	// We are only reading the ROM. Therefore the start address must be
	// higher than ROMSTART. Ignore addresses lower than this and
	// remove the offset for addresses we're interested in.
	if (nStartAddr >= Config.base_address)	//ROMSTART)
	{
		nStartAddr -= Config.base_address;		//ROMSTART;
		nEndAddr   -= Config.base_address;		//ROMSTART;
	}
	else
	{
		// The checksum block is outside our range
		return 0xffffffffu;
	}

	printf("%6x: ",nStartAddr);
	fflush(stdout);

	//Set the file pointer to the start block
	FSEEK(fh, nStartAddr, SEEK_SET);

	//Loop through the given addresses and work out the checksum
	for(nIndex = nStartAddr; nIndex <= nEndAddr; nIndex+=2)
	{
		FREAD(p, 2, 1, fh);
		nTemp = (p[1] << 8) + p[0];
		nChecksum += nTemp;
	}
	return nChecksum;
}

// vim:ts=4:sw=4
