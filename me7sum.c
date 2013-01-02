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
#include <errno.h>

#if _MSC_VER
#define snprintf _snprintf
#endif

#include "inifile_prop.h"
#include "crc32.h"
#include "utils.h"

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

// globals

static int ErrorsFound = 0;
static int ErrorsCorrected = 0;

// main firmware checksum validation
struct rom_config {
	int			readonly;
	uint32_t	base_address;				/* rom base address */
	uint32_t	multipoint_block_start;		/* start of multipoint block descriptors */
	uint32_t	multipoint_block_len;		/* size of descriptors */
	uint32_t	main_checksum_offset;		/* two start/end pairs, one at offset, other at offset+8 */
	uint32_t	main_checksum_final;		/* two 4 byte checksum (one inv) for two blocks conctatenated above) */
	struct {
		struct Range r;
		uint32_t	offset;
	} crc[3];								/* 3 CRC blocks to check */
} Config;

//
// List of configurable properties to read from config file into our programme...
// [this stops us having to hardcode values into the code itself]
//
PropertyListItem romProps[] = {
	// get rom region information
	{	GET_VALUE,  &Config.base_address,			"ignition", "rom_firmware_start",		"0"},
	{	GET_VALUE,  &Config.multipoint_block_start,	"ignition", "rom_checksum_block_start",	"0"},
	{	GET_VALUE,  &Config.multipoint_block_len,	"ignition", "rom_checksum_block_len",	"0x10"},
	{	GET_VALUE,  &Config.main_checksum_offset,	"ignition", "rom_checksum_offset",		"0"},
	{	GET_VALUE,  &Config.main_checksum_final,	"ignition", "rom_checksum_final",		"0"},
	{	GET_VALUE,  &Config.crc[0].r.start,			"ignition", "rom_crc1_start",			"0"},
	{	GET_VALUE,  &Config.crc[0].r.end,			"ignition", "rom_crc1_end",				"0"},
	{	GET_VALUE,  &Config.crc[0].offset,			"ignition", "rom_crc1",					"0"},
	{	GET_VALUE,  &Config.crc[1].r.start,			"ignition", "rom_crc2_start",			"0"},
	{	GET_VALUE,  &Config.crc[1].r.end,			"ignition", "rom_crc2_end",				"0"},
	{	GET_VALUE,  &Config.crc[1].offset,			"ignition", "rom_crc2",					"0"},
	{	GET_VALUE,  &Config.crc[2].r.start,			"ignition", "rom_crc3_start",			"0"},
	{	GET_VALUE,  &Config.crc[2].r.end,			"ignition", "rom_crc3_end",				"0"},
	{	GET_VALUE,  &Config.crc[2].offset,			"ignition", "rom_crc3",					"0"},
	{ END_LIST,   0, "",""},
};

static int GetRomInfo(struct ImageHandle *ih, struct section *osconfig,	uint32_t num_of);
static int DoMainCRCs(struct ImageHandle *ih);
static int DoMainChecksum(struct ImageHandle *ih);
static int DoChecksumBlks(struct ImageHandle *ih, uint32_t nStartBlk);

/*
 * main()
 *
 */

int main(int argc, char **argv)
{
	int	iTemp;
	int result;
	int num_of;
	struct ImageHandle ih;
	struct section *osconfig;

	// information about the tool
	printf("ME7Tool [ Management tool for Bosch ME7.x firmwares]\n");
	printf("Inspiration from Andy Whittaker's tools and information\n");
	printf("Written by 360trev and nyet [BSD License Open Source]. \n\n");

	if(argc < 4)
	{
		printf("Usage: %s <inrom.bin> <outrom.bin> <config.ini>\n",argv[0]);
		return -1;
	}

	printf("Attemping to open firmware config file %s\n",argv[3]);
	// load properties file into memory
	osconfig = read_properties(argv[3]);
	if(osconfig == NULL)
	{
		printf("failed to open config file\n");
		return -1;
	}

	// get rom region information from config file (see defined property list)
	result = process_properties_list(osconfig, romProps);

	// open the firmware file
	printf("\nAttemping to open firmware file %s\n",argv[1]);
	if (iload_file(&ih, argv[1], Config.readonly?0:1))
	{
		printf("failed to open firmware file\n");
		goto out;
	}

	// sanity check: validate firmware file is at least 512kbytes length before proceeding.
	if(ih.len < (1024*512)) {
		printf("File too small. Are you sure this is a firmware dump?\n");
		goto out;
	}

	//
	// Step #0 Show interesting ROM information
	//
	if ((num_of = get_property_value(osconfig, "dumps", "dump_show", NULL))>0)
	{
		printf("\nStep #0: Showing ROM info (typically ECUID Table)\n\n");
		result = GetRomInfo(&ih, osconfig, num_of);
	}
	else
	{
		printf("\nStep #0: Skipping ROM info... undefined\n");
	}

	//
	// Step #1 Main ROM CRCs if specified
	//
	if(Config.crc[0].r.start && Config.crc[0].r.end)
	{
		printf("\nStep #1: Reading main ROM CRC...\n");
		DoMainCRCs(&ih);
	}
	else
	{
		printf("\nStep #1: Skipping main ROM CRCs... undefined\n");
	}

	//
	// Step #2 Main ROM checksums
	//
	printf("\nStep #2: Reading main ROM checksum...\n");
	DoMainChecksum(&ih);

	//
	// Step #3 Multi point checksums
	//
	printf("\nStep #3: Reading Multipoint Checksum Block...\n");
	for(iTemp=0; iTemp<64; iTemp++)
	{
		printf("%2d) ",iTemp+1);
		fflush(stdout);
		result = DoChecksumBlks(&ih, Config.multipoint_block_start+(Config.multipoint_block_len*iTemp));
		if (result == 1) { break; } // end of blocks;
	}
	printf("[%d x <16> = %d bytes]\n", iTemp, iTemp*16);

	if(ErrorsCorrected > 0) {
		// write crc corrected file out
		save_file(argv[2],ih.d.p,ih.len);
	}

out:
	
	// close the file
	if(ih.d.p != 0) { ifree_file(&ih); }

	// free config
	if(osconfig != 0) { free_properties(osconfig); }

	printf("\nDone!\n%d/%d errors corrected!\n", ErrorsCorrected, ErrorsFound);

	return 0;
}

/*
 * GetRomInfo
 *
 * - uses config file to parse rom data and show interesting information about this rom dump
 */

static int GetRomInfo(struct ImageHandle *ih, struct section *osconfig,	uint32_t num_of)
{
	char str_data[1024];
	char type_str[256];
	char visible_str[256];
	char label_str[256];
	char offset_str[256];
	char length_str[256];
#ifdef DEBUG
	char * ptr_type;
#endif
	char * ptr_visible;
	char * ptr_label;
	uint32_t ptr_offset;
	uint32_t ptr_length;
	int i;

	if(ih == 0) return(-1);
	//
	// Dynamically walks through the config file and shows all properties defined...
	//
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
			// zero length, skip
		}
		else if(ptr_offset+ptr_length >= ih->len)
		{
			printf("%s = INVALID OFFSET/LEN 0x%x/%d\n",ptr_label, ptr_offset, ptr_length);
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
			/* snprintf null terminates for us if string is too long :) */
			snprintf(str_data, ptr_length, "%s", ih->d.s+ptr_offset);
			if(! strncmp("true",(char *)ptr_visible,4))
			{
				printf("%-20.20s '%s'\n",ptr_label, str_data);
			}
			else
			{
				printf("%s = 'HIDDEN'\n",ptr_label);
			}
		}
	}
	return 0;
}

static int DoMainCRCs(struct ImageHandle *ih)
{
	int result=0;
	int i;

	for (i=0; i<3; i++)
	{
		if(Config.crc[i].r.start && Config.crc[i].r.end)
		{
			uint32_t nCalcCRC;
			uint32_t nStart = Config.crc[i].r.start;
			size_t nLen = Config.crc[i].r.end - Config.crc[i].r.start + 1;
			uint32_t nCRCAddr = Config.crc[i].offset;
			uint32_t nCRC;
			uint32_t *p32;

			if (nStart>=Config.base_address)
			{
				nStart -= Config.base_address;
			}

			if (nCRCAddr>=Config.base_address)
			{
				nCRCAddr -= Config.base_address;
			}

			nCalcCRC = crc32(0, ih->d.u8+nStart, nLen);
			/* possibly unaligned, so we cant do tricks wtih ih->d.u32 */
			p32=(uint32_t *)(ih->d.u8 + nCRCAddr);
			nCRC=le32toh(*p32);
			printf("Adr: 0x%06X-0x%06X @0x%x CRC: 0x%08X  CalcCRC: 0x%08X",
				Config.crc[i].r.start, Config.crc[i].r.end, nCRCAddr, nCalcCRC, nCRC);
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

		}
	}
	return result;
}



//
// Calculate the Bosch Motronic ME71 checksum for the given range
//
static uint32_t CalcChecksumBlk(struct ImageHandle *ih, const struct Range *r)
{
	uint32_t	nStartAddr=r->start;
	uint32_t	nEndAddr=r->end;
	uint32_t	nChecksum = 0, nIndex;

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

	if(nStartAddr>=ih->len || nEndAddr>=ih->len)
	{
		// The checksum block is outside our range
		printf(" INVALID STARTADDDR/ENDADDR 0x%x/0x%x\n", nStartAddr, nEndAddr);
		return 0xffffffffu;
	}

	for(nIndex = nStartAddr/2; nIndex <= nEndAddr/2; nIndex++)
	{
		nChecksum+=le16toh(ih->d.u16[nIndex]);
	}
	return nChecksum;
}

//
// Reads the main checksum for the whole ROM
//
static int DoMainChecksum(struct ImageHandle *ih)
{
	int errors=0;
	struct Range r[2];
	struct ChecksumPair csum;
	uint32_t nCalcChksum;
	uint32_t nCalcChksum2;

	printf("ROM Checksum Block Offset Table 0x%X [16 bytes]\n\n",
		Config.main_checksum_offset);

	// C16x processors are little endian
	// copy from (le) buffer into our descriptor
	memcpy_from_le32(r, ih->d.u8+Config.main_checksum_offset, sizeof(r));

	// block 1
	nCalcChksum = CalcChecksumBlk(ih, r);
	printf("Adr: 0x%06X-0x%06X  Block #1 - nCalcChksum=0x%04x\n",
		r[0].start, r[0].end, nCalcChksum);

	if (r[0].end + 1 != r[1].start)
	{
		uint32_t skip=r[0].end+1;
		if (skip >= Config.base_address)
		{
			skip-=Config.base_address;
		}
		printf("Adr: 0x%06X-0x%06X  MAP REGION SKIPPED, NOT PART OF MAIN CHECKSUM\n",
			r[0].end+1, r[1].start-1);
	}

	// block 2
	nCalcChksum2= CalcChecksumBlk(ih, r+1);
	printf("Adr: 0x%06X-0x%06X  Block #2 - nCalcChksum=0x%04x\n",
		r[1].start, r[1].end,nCalcChksum2);

	nCalcChksum += nCalcChksum2;
	printf("\nRead in stored MAIN ROM checksum block @ 0x%X [8 bytes]\n",
		Config.main_checksum_final);

	// C16x processors are little endian
	// copy from (le) buffer
	memcpy_from_le32(&csum, ih->d.u8+Config.main_checksum_final, sizeof(csum));

	printf("Chksum : 0x%08X", csum.v);
	if(csum.v != ~csum.iv)
	{
		printf(" ~Chksum : 0x%08X INV NOT OK", csum.iv);
		errors++;
	}

	printf(" CalcChk: 0x%08X", nCalcChksum);

	if(csum.v != nCalcChksum) { errors++; }

	if(!errors)
	{
		printf("  Main ROM checksum OK\n");
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

	memcpy_to_le32(ih->d.u8+Config.main_checksum_final, &csum, sizeof(csum));

	printf(" ** FIXED! **\n");
	ErrorsCorrected+=errors;
	return 0;
}

// Reads the individual checksum blocks that start at nStartBlk
static int DoChecksumBlks(struct ImageHandle *ih, uint32_t nStartBlk)
{
	// read the ROM byte by byte to make this code endian independant
	// C16x processors are little endian
	struct MultipointDescriptor desc;
	uint32_t nCalcChksum;
	int errors=0;

	printf("<%x> ",nStartBlk);
	fflush(stdout);

	if(nStartBlk + sizeof(desc) >= ih->len)
	{
		printf(" INVALID STARTBLK/LEN 0x%x/%ld ** NOT OK **\n", nStartBlk, (long int)ih->len);
		return -1;	// Uncorrectable Error
	}

	// C16x processors are little endian
	// copy from (le) buffer into our descriptor
	memcpy_from_le32(&desc, ih->d.u8+nStartBlk, sizeof(desc));

	printf("Adr: 0x%04X-0x%04X ", desc.r.start, desc.r.end);
	fflush(stdout);

	if(desc.r.start==0xffffffff)
	{
		printf(" END\n");
		return 1;	// end of blks
	}

	if(desc.r.start>=desc.r.end)
	{
		printf(" ** NOT OK **\n");
		return -1;	// Uncorrectable Error
	}

	printf("Chk: 0x%08X", desc.csum.v);

	if(desc.csum.v != ~desc.csum.iv)
	{
		printf("  ~0x%08X INV NOT OK", desc.csum.iv);
		errors++;
	}

	// calc checksum
	nCalcChksum = CalcChecksumBlk(ih, &desc.r);

	printf(" CalcChk: 0x%08X", nCalcChksum);
	if(desc.csum.v != nCalcChksum) { errors++; }

	if (!errors)
	{
		printf("  OK\n");
		return 0;
	}

	ErrorsFound+=errors;

	if (Config.readonly)
	{
		printf(" ** NOT OK **\n");
		return -1;
	}

	desc.csum.v = nCalcChksum;
	desc.csum.iv = ~nCalcChksum;
	memcpy_to_le32(ih->d.u8+nStartBlk, &desc, sizeof(desc));

	printf(" ** FIXED! **\n");
	ErrorsCorrected+=errors;
	return 0;
}

// vim:ts=4:sw=4
