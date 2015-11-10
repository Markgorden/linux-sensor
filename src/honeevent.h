/*
 * Copyright (C) 2011 Battelle Memorial Institute
 * Copyright (C) 2015 Google Inc.
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 *
 * Author: Brandon Carpenter
 */

#ifndef _HONEEVENT_H
#define _HONEEVENT_H

enum { IGNORE = 0, AGGREGATE, REMOVE, ENABLE_AGGREGATE, DISABLE_AGGREGATE};

struct sock_argv {
	uint64_t sock;
	uint32_t action;
	uint32_t aggregate_sec;
};

#define HEIO_RESTART _IO(0xE0, 0x01)
#define HEIO_GET_AT_HEAD _IO(0xE0, 0x03)
#define HEIO_GET_SNAPLEN _IOR(0xE0, 0x04, int)
#define HEIO_SET_SNAPLEN _IOW(0xE0, 0x05, int)
#define HEIO_SOCK_FILTER _IOW(0xE0, 0x07, struct sock_argv)
#define HEIO_STATS _IO(0xE0, 0x8)

#endif /* _HONEEVENT_H */
