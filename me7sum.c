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
#include <ctype.h>	/* isprint() */

#if _MSC_VER
#define snprintf _snprintf
#include "os/getopt.h"
#else
#include <getopt.h>
#endif

#include "inifile_prop.h"
#include "crc32.h"
#include "utils.h"

//#define DEBUG_ROM_INFO
//#define DEBUG_CRC_MATCHING
//#define DEBUG_MAIN_MATCHING
//#define DEBUG_MULTIPOINT_MATCHING

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

#define MAX_CRC_BLKS 4
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
	} crc[MAX_CRC_BLKS+1];					/* 0/4 is pre-region (for kbox and other) Up to 5 CRC blocks (total) to check */
} Config;

//
// List of configurable properties to read from config file into our programme...
// [this stops us having to hardcode values into the code itself]
//
static PropertyListItem romProps[] = {
	// get rom region information
	{	GET_VALUE,  &Config.base_address,			"ignition", "rom_firmware_start",		"0x800000"},
	{	GET_VALUE,  &Config.multipoint_block_start,	"ignition", "rom_checksum_block_start",	"0"},
	{	GET_VALUE,  &Config.multipoint_block_len,	"ignition", "rom_checksum_block_len",	"0x10"},
	{	GET_VALUE,  &Config.main_checksum_offset,	"ignition", "rom_checksum_offset",		"0"},
	{	GET_VALUE,  &Config.main_checksum_final,	"ignition", "rom_checksum_final",		"0"},
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

static int GetRomInfo(struct ImageHandle *ih, struct section *osconfig,	uint32_t num_of);

static int FindMainCRCPreBlk(const struct ImageHandle *ih);
static int FindMainCRCBlks(const struct ImageHandle *ih);
static int FindMainCRCOffsets(const struct ImageHandle *ih);
static int DoMainCRCs(struct ImageHandle *ih);

static int FindMainRomOffset(const struct ImageHandle *ih);
static int FindMainRomFinal(const struct ImageHandle *ih);
static int DoMainChecksum(struct ImageHandle *ih, uint32_t nOffset, uint32_t nCsumAddr);

static int FindChecksumBlks(const struct ImageHandle *ih);
static int DoChecksumBlk(struct ImageHandle *ih, uint32_t nStartBlk);

/*
 * main()
 *
 */

static void usage(const char *prog)
{
	printf("Usage: %s [-i <config.ini>] <inrom.bin> [outrom.bin]\n", prog);
	exit(-1);
}

int main(int argc, char **argv)
{
	int	iTemp;
	int result;
	int num_of;
	char *prog=argv[0];
	char *inifile=NULL;
	char *input=NULL;
	char *output=NULL;
	char c;
	struct ImageHandle ih;
	struct section *osconfig=NULL;

	// information about the tool
	printf("ME7Tool [ Management tool for Bosch ME7.x firmwares]\n");
	printf("Inspiration from Andy Whittaker's tools and information\n");
	printf("Written by 360trev and nyet [BSD License Open Source]. \n\n");

	opterr=0;

	while ((c = getopt(argc, argv, "i:")) != -1)
	{
		switch (c)
		{
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
		printf("Attemping to open firmware config file %s\n",inifile);
		// load properties file into memory
		osconfig = read_properties(inifile);
		if(osconfig == NULL)
		{
			printf("failed to open config file\n");
			return -1;
		}
	}

	// get rom region information from config file (see defined property list)
	result = process_properties_list(osconfig, romProps);

	// open the firmware file
	printf("\nAttemping to open firmware file %s\n",input);
	if (iload_file(&ih, input, 0))
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
	printf("\nStep #1: Reading main ROM CRC...\n");

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
		FindMainCRCOffsets(&ih);
	}

	if(Config.crc[1].r.start && Config.crc[1].r.end && Config.crc[1].offset)
	{
		DoMainCRCs(&ih);
	}
	else
	{
		printf("\nStep #1: Skipping main ROM CRCs... undefined\n");
	}

#ifdef DEBUG_CRC_MATCHING
	exit (-1);
#endif

	//
	// Step #2 Main ROM checksums
	//
	printf("\nStep #2: Reading main ROM checksum...\n");
	if(Config.main_checksum_offset==0)
	{
		FindMainRomOffset(&ih);
	}

	if(Config.main_checksum_final==0)
	{
		FindMainRomFinal(&ih);
	}

	if (Config.main_checksum_offset && Config.main_checksum_final)
	{
		DoMainChecksum(&ih, Config.main_checksum_offset, Config.main_checksum_final);
	}
	else
	{
		printf("Skipping main ROM checksum... undefined\n");
	}

#ifdef DEBUG_MAIN_MATCHING
	exit (-1);
#endif

	//
	// Step #3 Multi point checksums
	//
	printf("\nStep #3: Reading Multipoint Checksum Block...\n");

	if(Config.multipoint_block_start==0)
	{
		FindChecksumBlks(&ih);
	}

	if(Config.multipoint_block_start)
	{
		for(iTemp=0; iTemp<64; iTemp++)
		{
			printf("%2d) ",iTemp+1);
			fflush(stdout);
			result = DoChecksumBlk(&ih, Config.multipoint_block_start+(Config.multipoint_block_len*iTemp));
			if (result == 1) { break; } // end of blocks;
		}
		printf("[%d x <16> = %d bytes]\n", iTemp, iTemp*16);
	}
	else
	{
		printf("Skipping Multipoint Checksum Block... undefined\n");
	}

#ifdef DEBUG_MULTIPOINT_MATCHING
	exit (-1);
#endif

	if(output && ErrorsCorrected > 0) {
		// write crc corrected file out
		save_file(output,ih.d.p,ih.len);
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
#ifdef DEBUG_ROM_INFO
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
			// restrict maximum dump to 1kbyte [buffer size]
			if(ptr_length > 1024) ptr_length = 1024;
#ifdef DEBUG_ROM_INFO
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

static int FindMainCRCData(const struct ImageHandle *ih, const char *what,
	const uint8_t *n, const uint8_t *m, int len,	// needle, mask, len of needle/mask
	int off_l, int off_h,							// where to find hi/lo (short word offset into find array)
	uint32_t *offset, int offset_len,				// array to store discovered offsets, len of array
	uint32_t *where)								// address of match (ONLY if single match), NULL if not needed
{
	/* Note that off_l and off_h are SHORT WORD offsets, i.e. 1 == 2 bytes */

	int i, found=0;
	uint32_t last_where=0;

	for(i=0;i+len<ih->len;i+=2)
	{
		i=search_image(ih, i, n, m, len, 2);
		if (i<0) break;
		if (i+len<ih->len)
		{
			uint16_t low=le16toh(ih->d.u16[i/2+off_l]);
			uint16_t high=le16toh(ih->d.u16[i/2+off_h]);
			uint32_t addr=(high<<16) | low;

#ifdef DEBUG_CRC_MATCHING
			printf("Found possible %s #%d at 0x%x (from 0x%x)\n", what, found+1, addr, i);
			hexdump(ih->d.u8+i-4, 4, " [");
			hexdump(ih->d.u8+i, len, "] ");
			hexdump(ih->d.u8+i+1, 4, "\n");
#endif
			if (addr>Config.base_address) {
				if(found<offset_len)
				{
					offset[found]=addr;
					last_where = i;
				}
				found++;
			}
		}
	}
	if (found==1 && where) *where=last_where;
	return found;
}

static int FindMainCRCPreBlk(const struct ImageHandle *ih)
{
	int found;
	uint32_t offset;
	uint32_t where=0;
	//                                LL    LL                HH    HH          s
	uint8_t needle[] = {0xE6, 0xFC, 0x00, 0x00, 0xE6, 0xFD, 0x00, 0x00, 0xE0, 0x0E, 0xDA, 0x00, 0x00, 0x00, 0xF6, 0xF4};
	uint8_t   mask[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0x0f, 0xFF, 0x00, 0x00, 0x00, 0xff, 0xff};

	printf("Searching for main ROM CRC pre block...\n");

	found=FindMainCRCData(ih, "CRC pre block", needle, mask, sizeof(needle), 1, 3, &offset, 1, &where);

	if (found==1)
	{
		// crc0 is reserved for pre-region
		Config.crc[0].r.start=offset;
		Config.crc[0].r.end=offset+(ih->d.u8[where+9]>>4)-1;
#ifdef DEBUG_CRC_MATCHING
		printf("Found %s #%d 0x%x-0x%x (0x%x)\n", "CRC pre block", 0, offset, Config.crc[0].r.end, where);
#endif
		return 0;
	}

	if (found>1)
	{
		printf("Too many matches (%d). CRC block start find failed\n", found);
	}
	return -1;
}

static int FindMainCRCBlks(const struct ImageHandle *ih)
{
	int i, found, ret0=-1, ret1=-1;
	uint32_t offset[MAX_CRC_BLKS];
	//                            LL    LL                HH
	uint8_t n0[] = {0xE6, 0xF8, 0x00, 0x00, 0xE6, 0xF9, 0x00, 0x00, 0xF2, 0xF4, 0x00, 0x00, 0x24, 0x8F};
	uint8_t m0[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff};
	//                                        LL    LL                HH
	uint8_t n1[] = {0x10, 0x9B, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x00, 0x00, 0x26, 0xF4};
	uint8_t m1[] = {0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff};

	printf("Searching for main ROM CRC block starts...\n");

	found=FindMainCRCData(ih, "CRC block starts", n0, m0, sizeof(n0), 1, 3, offset, MAX_CRC_BLKS, NULL);

	if (found>0 && found<=MAX_CRC_BLKS)
	{
		for (i=0;i<found;i++)
		{
#ifdef DEBUG_CRC_MATCHING
			printf("Found %s #%d at 0x%x\n", "CRC block start", i+1, offset[i]);
#endif
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].r.start=offset[i];
			ret0=0;
		}
	}

	if (found>MAX_CRC_BLKS)
	{
		printf("Too many matches (%d). CRC block start find failed\n", found);
	}

	printf("Searching for main ROM CRC block ends...\n");

	found=FindMainCRCData(ih, "CRC block end", n1, m1, sizeof(n1), 2, MAX_CRC_BLKS, offset, 4, NULL);

	if (found>0 && found<=MAX_CRC_BLKS)
	{
		for (i=0;i<found;i++)
		{
#ifdef DEBUG_CRC_MATCHING
			printf("Found %s #%d at 0x%x\n", "CRC block end", i+1, offset[i]);
#endif
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].r.end=offset[i];
			ret1=0;
		}
	}

	if (found>MAX_CRC_BLKS)
	{
		printf("Too many matches (%d). CRC block end find failed\n", found);
	}

	return ret0 & ret1;
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
	uint8_t needle[] = {0xF6, 0xF5, 0x00, 0x00, 0xE6, 0xF4, 0x00, 0x00, 0xE6, 0xF5, 0x00, 0x00, 0xDA, 0x00, 0xD8, 0x7E};
	uint8_t   mask[] = {0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};

	printf("Searching for main ROM CRC offsets...\n");

	found=FindMainCRCData(ih, "CRC offset", needle, mask, sizeof(needle), 3, 5, offset, MAX_CRC_OFFSETS, NULL);

	if (found>0 && found<=MAX_CRC_OFFSETS)
	{
		for (i=0;i<found;i++)
		{
#ifdef DEBUG_CRC_MATCHING
			printf("Found CRC #%d at 0x%x\n", i+1, offset[i]);
#endif
			// crc0 is reserved for pre-region
			if (i<MAX_CRC_BLKS)
				Config.crc[i+1].offset=offset[i];
		}
	}

	if (found!=3)
	{
		printf("Did not find exactly 3 matches (got %d). CRC offset find failed\n", found);
#ifndef DEBUG_CRC_MATCHING
		memset(Config.crc, 0, sizeof(Config.crc));
#endif
		return -1;
	}

	/* if we found exactly 3 crc values, and region 4 exists, use region 3's crc for calcing 3+4 */
	if (Config.crc[4].r.start && Config.crc[4].r.end) {
		Config.crc[4].offset=Config.crc[3].offset;
		Config.crc[3].offset=0;
	}

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

			if (nStart>=Config.base_address)
			{
				nStart -= Config.base_address;
			}

			if (nCRCAddr>=Config.base_address)
			{
				nCRCAddr -= Config.base_address;
			}

			nCalcCRC = crc32(nCalcCRCSeed, ih->d.u8+nStart, nLen);

			printf("%d: Adr: 0x%06X-0x%06X", i, Config.crc[i].r.start, Config.crc[i].r.end);

			if (nCRCAddr+4>ih->len)
			{
				printf(" @0x%x INVALID ADDRESS\n", nCRCAddr);
			}
			else if (nCRCAddr)
			{
				/* possibly unaligned, so we cant do tricks wtih ih->d.u32 */
				p32=(uint32_t *)(ih->d.u8 + nCRCAddr);
				nCRC=le32toh(*p32);

				printf(" @0x%x CRC: %08X  CalcCRC: %08X (seed %08X)", nCRCAddr, nCRC, nCalcCRC, nCalcCRCSeed);

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
				printf("                         CalcCRC: %08X (seed %08X)\n", nCalcCRC, nCalcCRCSeed);
			}

			if (Config.crc[4].r.start && Config.crc[4].r.end)
				nCalcCRCSeed=nCalcCRC;
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

static int FindMainRomOffset(const struct ImageHandle *ih)
{
	int i, found=0, offset=0;
	uint32_t needle[4];
	uint32_t mask[4];

	printf("Searching for main ROM checksum...\n");

	needle[0]=htole32(Config.base_address);
	needle[1]=htole32(Config.base_address+0x0f000);
	needle[2]=htole32(Config.base_address+0x20000);
	needle[3]=htole32(Config.base_address+0x7ffff);
	mask[0]=htole32(0xffffffff);
	mask[1]=htole32(0xfffff000);
	mask[2]=htole32(0xffffffff);
	mask[3]=htole32(0xfff7ffff);

	for(i=0;i+sizeof(needle)<ih->len;i+=2)
	{
		i=search_image(ih, i, needle, mask, sizeof(needle), 2);
		if (i<0) break;
		if (i+sizeof(needle)<ih->len)
		{
#ifdef DEBUG_MAIN_MATCHING
			printf("Found possible main block descriptor at 0x%x\n", i);
#endif
			offset=i;
			found++;
		}
	}

	if (found==1)
	{
#ifdef DEBUG_MAIN_MATCHING
		printf("Found main block descriptor at 0x%x\n", offset);
#endif
		Config.main_checksum_offset=offset;
		return 0;
	}

	return -1;
}

static int FindMainRomFinal(const struct ImageHandle *ih)
{
	int offset=ih->len-0x20;
	struct ChecksumPair *csum = (struct ChecksumPair *)(ih->d.u8+offset);

	if (csum->v == ~csum->iv)
	{
#ifdef DEBUG_MAIN_MATCHING
		printf("Found main csum at 0x%x\n", offset);
#endif
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

	printf("ROM Checksum Block Offset Table 0x%X [16 bytes]\n\n",
		Config.main_checksum_offset);

	// C16x processors are little endian
	// copy from (le) buffer into our descriptor
	memcpy_from_le32(r, ih->d.u8+nOffset, sizeof(r));

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
	memcpy_from_le32(&csum, ih->d.u8+nCsumAddr, sizeof(csum));

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

	memcpy_to_le32(ih->d.u8+nCsumAddr, &csum, sizeof(csum));

	printf(" ** FIXED! **\n");
	ErrorsCorrected+=errors;
	return 0;
}

static int FindChecksumBlks(const struct ImageHandle *ih)
{
	int i, found=0, offset=0;
	uint32_t needle[2];

	needle[0]=htole32(Config.base_address);
	needle[1]=htole32(Config.base_address+0x3fff);

	for(i=0;i+Config.multipoint_block_len<ih->len;i+=2)
	{
		i=search_image(ih, i, needle, NULL, sizeof(needle), 2);
		if (i<0) break;
		if (i+Config.multipoint_block_len<ih->len)
		{
			struct MultipointDescriptor *desc =
				(struct MultipointDescriptor *)(ih->d.u8+i);

			if (desc->csum.v==~desc->csum.iv)
			{
				offset=i;
				found++;
			}
		}
	}

	if (found==1)
	{
		/* test next block to make sure it looks reasonable */
		struct MultipointDescriptor *desc =
			(struct MultipointDescriptor *)(ih->d.u8+offset+Config.multipoint_block_len);

		if (desc->csum.v==~desc->csum.iv)
		{
#ifdef DEBUG_MULTIPIONT_MATCHING
			printf("Found descriptor at 0x%x\n", offset);
#endif
			Config.multipoint_block_start=offset;
			return 0;
		}
	}

	return -1;
}

// Reads the individual checksum blocks that start at nStartBlk
static int DoChecksumBlk(struct ImageHandle *ih, uint32_t nStartBlk)
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
