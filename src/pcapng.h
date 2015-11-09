/*
 * Copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

#ifndef _PCAPNG_H
#define _PCAPNG_H

#include <asm/atomic.h>
#include <linux/time.h>

#define HONE_USER_HEAD (HONE_USER | 1)
#define HONE_USER_TAIL (HONE_USER | 2)

#define GUID_FMT "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GUID_TUPLE(G) (G)->data1, (G)->data2, (G)->data3, \
		(G)->data4[0], (G)->data4[1], (G)->data4[2], (G)->data4[3], \
		(G)->data4[4], (G)->data4[5], (G)->data4[6], (G)->data4[7]

struct guid_struct {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t  data4[8];
};

struct device_info {
	struct guid_struct host_guid;
	bool host_guid_is_set;
	const char *host_id;
	const char *comment;
};

struct reader_info {
	unsigned int snaplen;
	struct timespec boot_time;
	struct timespec start_time;
	struct statistics delivered;  /* events sent to userland */
	struct statistics dropped;    /* events we weren't able to send to userland */
	atomic64_t filtered;          /* packets filtered */
	atomic64_t aggregated;        /* packets aggregated */
	atomic64_t ioctl;             /* ioctl messages received */
	atomic64_t pending_work;      /* pending tasks in the hone_wq */
};

unsigned int format_as_pcapng(
		const struct device_info *devinfo, struct reader_info *info,
		struct hone_event *event, char *buf, unsigned int buflen);
int parse_guid(struct guid_struct *guid, const char *input);

#endif /* _PCAPNG_H */
