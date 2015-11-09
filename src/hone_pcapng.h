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

// TODO(binp): Define macros for all hard-coded integers.

#endif /* _HONE_PCAPNG_H */
