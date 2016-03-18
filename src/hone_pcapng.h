/*
 * Copyright (C) 2016 Google Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef _HONE_PCAPNG_H
#define _HONE_PCAPNG_H

#define HONE_BYTE_ORDER_MAGIC  0x1A2B3C4D
#define HONE_OPT_HDR_LEN       4
#define HONE_OPT_EXTRA_LEN     16
#define HONE_PROC_OPT_MAX_LEN  4096

#define HONE_VERSION_MAJOR     1
#define HONE_VERSION_MINOR     0

#define HONE_IF_DESC_BLOCK     0x1
#define HONE_IF_STATS_BLOCK    0x5
#define HONE_PACKET_BLOCK      0x6
#define HONE_AGGREGATE_BLOCK   0x7
#define HONE_PROCESS_BLOCK     0x101
#define HONE_CONNECTION_BLOCK  0x102
#define HONE_SECTION_HDR_BLOCK 0x0A0D0D0A

#endif /* _HONE_PCAPNG_H */
