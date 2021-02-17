#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "range.h"

static LIST_HEAD(Records);

#define MAX_NAME_LENGTH 256

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

// Tests if a newly discovered record checksum location is in an already
// checksummed data.
// This means we found a checksum that, if corrected, will cause a previously
// calculated checksum to be wrong!
static int test_for_data_overlap(const struct ReportRecord *rec, struct list_head *records)
{
	int ret=0;
	const struct Range *csum = &rec->checksum;
	struct ReportRecord *rr;
	list_for_each_entry(rr, records, list) {
		const struct RangeList *rl;
		if (strncmp(rec->name, rr->name, MAX_NAME_LENGTH)) {
			list_for_each_entry(rl, &rr->data.list, list) {
				const struct Range *data = &rl->r;
				if (MAX(csum->start, data->start)<=MIN(csum->end, data->end)) {
					sbprintf(&rr->msg, "%d-%s checksum is in %d-%s data (recheck required): (0x%08x-0x%08x) overlaps with (0x%08x-0x%08x)\n",
						rec->index, rec->name, rr->index, rr->name,
						csum->start, csum->end,
						data->start, data->end);
					rr->deps ++;
					ret ++;
					// exit(-1);
				}
			}
		}
	}
	return ret;
}

// Tests if new data range is in an already calculated checksum
// This is expected.
static int test_for_csum_overlap(struct ReportRecord *rec, struct list_head *records, const struct Range *data)
{
	int ret=0;
	struct ReportRecord *rr;
	list_for_each_entry(rr, records, list) {
		if (strncmp(rec->name, rr->name, MAX_NAME_LENGTH)) {
			const struct Range *csum = &rr->checksum;
			if (MAX(csum->start, data->start)<=MIN(csum->end, data->end)) {
				sbprintf(&rec->msg, "%d-%s checksum is in %d-%s data: (0x%08x-0x%08x) overlaps with (0x%08x-0x%08x)\n",
					rr->index, rr->name, rec->index, rec->name,
					csum->start, csum->end,
					data->start, data->end);
				ret ++;
				// exit(-1);
			}
		}
	}
	return ret;
}

struct ReportRecord *CreateRecord(const char *name, uint32_t start, int len)
{
	struct ReportRecord *rr = calloc(1, sizeof(struct ReportRecord));
	//fprintf(stderr,"******* CREATE %s *******\n", name);
	rr->name = strndup(name, MAX_NAME_LENGTH);
	INIT_LIST_HEAD(&rr->data.list);
	rr->checksum.start = start;
	rr->checksum.end = start+len-1;
	rr->index = list_entry(Records.prev, struct ReportRecord, list)->index+1;

	// check if this new checksum is in existing data ranges
	test_for_data_overlap(rr, &Records);

	list_add_tail(&rr->list, &Records);
	return rr;
}

void PrintRecord(FILE *fh, struct ReportRecord *rr)
{
	struct RangeList *rl;

	if (!fh) return;

	fprintf(fh, "0x%08x-0x%08x %s CSUM\n", rr->checksum.start, rr->checksum.end, rr->name);
	if(rr->msg.pbuf) fprintf(fh, "%s", rr->msg.pbuf);
	list_for_each_entry(rl, &rr->data.list, list) {
		fprintf(fh, " 0x%08x-0x%08x\n", rl->r.start, rl->r.end);
	}
	return;
}

void AddRange(struct ReportRecord *rr, struct Range *r)
{
	struct RangeList *rl = calloc(1, sizeof(struct RangeList));
	rl->r = *r;	/* memcpy */

	// check if this new data range is in existing checksum ranges
	test_for_csum_overlap(rr, &Records, &rl->r);

	list_add_tail(&rl->list, &rr->data.list);
}

void AddRangeStartEnd(struct ReportRecord *rr, uint32_t start, uint32_t end)
{
	struct RangeList *rl = calloc(1, sizeof(struct RangeList));
	rl->r.start = start;
	rl->r.end = end;

	// check if this new data range is in existing checksum ranges
	test_for_csum_overlap(rr, &Records, &rl->r);

	list_add_tail(&rl->list, &rr->data.list);
}

void AddRangeStartLength(struct ReportRecord *rr, uint32_t start, int len)
{
	struct RangeList *rl = calloc(1, sizeof(struct RangeList));
	rl->r.start = start;
	rl->r.end = start+len-1;

	// check if this new data range is in existing checksum ranges
	test_for_csum_overlap(rr, &Records, &rl->r);

	list_add_tail(&rl->list, &rr->data.list);
}

static void FreeRecord(struct ReportRecord *rr)
{
	struct RangeList *rl, *tmp;
	list_for_each_entry_safe(rl, tmp, &rr->data.list, list) {
		//struct RangeList *rl = list_entry(e, struct RangeList, list);
		list_del(&rl->list);
		free(rl);
	}
	if (rr->name) free(rr->name);
	if (rr->msg.pbuf) free(rr->msg.pbuf);
	free(rr);
}

void PrintAllRecords(FILE *fh)
{
	struct ReportRecord *rr;
	list_for_each_entry(rr, &Records, list) {
		PrintRecord(fh, rr);
	}
}

void FreeAllRecords(void)
{
	struct ReportRecord *rr, *tmp;
	list_for_each_entry_safe(rr, tmp, &Records, list) {
		list_del(&rr->list);
		FreeRecord(rr);
	}
}

int ProcessRecordDeps(void)
{
	int errs=0;
	struct ReportRecord *rr;
	list_for_each_entry(rr, &Records, list) {
		if (rr->deps) {
			if (rr->callback) {
				errs += rr->callback(rr->cb_data, rr);
			} else {
				printf("%s: no callback for recheck\n", rr->name);
				errs++;
			}
			printf("*** WARNING! %s\n", rr->msg.pbuf);
		}
	}
	return errs;
}

// vim:ts=4:sw=4:noexpandtab
