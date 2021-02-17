#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "range.h"

static LIST_HEAD(Records);

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))
static int test_for_overlap(const char *name, struct list_head *records, const struct Range *a)
{
	int ret=0;
	struct ReportRecord *rr;
	list_for_each_entry(rr, records, list) {
		struct RangeList *rl;
		list_for_each_entry(rl, &rr->data.list, list) {
			const struct Range *b = &rl->r;
			if (MAX(a->start, b->start)<=MIN(a->end, b->end)) {
				sbprintf(&rr->msg, "%s checksum 0x%08x-0x%08x is in my data\n",
					name, a->start, a->end);
				rr->deps ++;
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
	rr->name = strdup(name);
	INIT_LIST_HEAD(&rr->data.list);
	rr->checksum.start = start;
	rr->checksum.end = start+len-1;

	test_for_overlap(name, &Records, &rr->checksum);

	list_add_tail(&rr->list, &Records);
	return rr;
}

void PrintRecord(FILE *fh, struct ReportRecord *rr)
{
	struct RangeList *rl;

	if (!fh) return;

	fprintf(fh, "0x%08x-0x%08x %s\n", rr->checksum.start, rr->checksum.end, rr->name);
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
	list_add_tail(&rl->list, &rr->data.list);
}

void AddRangeStartEnd(struct ReportRecord *rr, uint32_t start, uint32_t end)
{
	struct RangeList *rl = calloc(1, sizeof(struct RangeList));
	rl->r.start = start;
	rl->r.end = end;
	list_add_tail(&rl->list, &rr->data.list);
}

void AddRangeStartLength(struct ReportRecord *rr, uint32_t start, int len)
{
	struct RangeList *rl = calloc(1, sizeof(struct RangeList));
	rl->r.start = start;
	rl->r.end = start+len-1;
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
			int ret = 0;
			if (rr->callback) {
				ret = rr->callback(rr->cb_data, rr);
			} else {
				printf("%s: no callback for recheck\n", rr->name);
				ret = -1;
			}

			if (ret) {
				if (rr->msg.pbuf)
					printf("%s", rr->msg.pbuf);
				errs++;
			}
		}
	}
	return errs;
}

// vim:ts=4:sw=4
