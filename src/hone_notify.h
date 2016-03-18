/*
 * Copyright (C) 2011 Battelle Memorial Institute
 * Copyright (C) 2016 Google Inc.
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 *
 * Author: Brandon Carpenter
 */

#ifndef _HONE_NOTIFY_H
#define _HONE_NOTIFY_H

#include <linux/in6.h>

#define pr_line() printk(KERN_DEBUG "%s: %s:%d %s\n", THIS_MODULE->name, __FILE__, __LINE__, __FUNCTION__)

#define HONE_PROCESS 1
#define HONE_SOCKET 2
#define HONE_PACKET 3
#define HONE_SOCKET_AGGREGATE 4
#define HONE_USER 0x8000

extern struct workqueue_struct *hone_wq;

struct sock_aggregate_event {
	unsigned long sock;
	pid_t pid;
	struct timespec start;
	struct timespec end;
	uint8_t ip_version;
	uint8_t protocol;
	uint16_t padding;
	struct in6_addr saddr;
	struct in6_addr daddr;
	uint16_t source;        // source port number in host byte order.
	uint16_t dest;          // dest port number in host byte order.
	uint32_t pkts_in;
	uint32_t pkts_out;
	uint32_t bytes_in;
	uint32_t bytes_out;
};

struct process_event {
	struct mm_struct *mm;
	int code;  /* On process exit, this is this return code. */
	int signaled;  /* On process exit, this is if the process was killed by an
			  uncatchable signal */
	char *cwd;
	int event;
	pid_t pid;
	pid_t ppid;
	pid_t tgid;
	uid_t uid;
	uid_t euid;
	uid_t loginuid;
	gid_t gid;
};

struct socket_event {
	unsigned long sock;
	int event;
	pid_t pid;
	pid_t ppid;
	pid_t tgid;
	uid_t uid;
	gid_t gid;
};

struct packet_event {
	unsigned long sock;
	int dir;
	pid_t pid;
	struct sk_buff *skb;
};

struct user_event {
	void *data;
};

struct hone_event {
	int type;
	union {
		atomic_t users;
		struct hone_event *next;
	};
	struct timespec ts;
	union {
		struct process_event process;
		struct socket_event socket;
		struct packet_event packet;
		struct user_event user;
		struct sock_aggregate_event agg;
	};
};

#ifdef __KERNEL__

struct statistics {
	atomic64_t process;
	atomic64_t socket;
	atomic64_t packet;
	atomic64_t aggregate;
};

#define STATISTICS_INIT {ATOMIC64_INIT(0), ATOMIC64_INIT(0), ATOMIC64_INIT(0), ATOMIC64_INIT(0)}
#define DEFINE_STATISTICS(name) struct statistics name = STATISTICS_INIT

static inline void init_statistics(struct statistics *stats)
{
	atomic64_set(&stats->process, 0);
	atomic64_set(&stats->socket, 0);
	atomic64_set(&stats->packet, 0);
	atomic64_set(&stats->aggregate, 0);
}

extern void get_hone_statistics(struct statistics *received,
		struct statistics *dropped, struct timespec *ts);
extern int hone_notifier_register(struct notifier_block *nb);
extern int hone_notifier_unregister(struct notifier_block *nb);

extern struct hone_event *alloc_hone_event(unsigned int type, gfp_t flags);
extern void free_hone_event(struct hone_event *event);
extern struct hone_event *__alloc_process_event(
		struct process_args *pargs, int type, gfp_t flags);
extern struct hone_event *__alloc_socket_event(unsigned long sock, int type,
		struct task_struct *task, gfp_t flags);

static inline void get_hone_event(struct hone_event *event)
{
	BUG_ON(unlikely(!atomic_read(&event->users)));
	atomic_inc(&event->users);
}

static inline void put_hone_event(struct hone_event *event)
{
	BUG_ON(unlikely(!atomic_read(&event->users)));
	if (atomic_dec_and_test(&event->users))
		free_hone_event(event);
}


#endif /* __KERNEL__ */

#endif /* _HONE_NOTIFY_H */
