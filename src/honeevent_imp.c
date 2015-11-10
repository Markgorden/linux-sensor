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

#include <linux/version.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/stringify.h>
#include <linux/time.h>
#include <linux/poll.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/hashtable.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "process_notify.h"
#include "packet_notify.h"
#include "hone_notify.h"
#include "honeevent.h"
#include "mmutil.h"
#include "ringbuf.h"
#include "pcapng.h"
#include "version.h"

MODULE_DESCRIPTION("Hone event character device.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HONE_VERSION);
MODULE_ALIAS("hone");

static char version[] __initdata = HONE_VERSION;

static char *devname = "hone";
module_param(devname, charp, S_IRUGO);
MODULE_PARM_DESC(devname, "The name to give the device in sysfs (default: hone).");

static int major = 0;
module_param(major, int, S_IRUGO);
MODULE_PARM_DESC(major, "The major number to give the device.  "
		"If 0 (the default), the major number is automatically assigned by the kernel.");

static char hostid_type = 0;
module_param(hostid_type, byte, S_IRUGO);
MODULE_PARM_DESC(hostid_type,
		"An integer describing how to interpret the value of hostid.  0 (the "
		"default) means hostid is a string while 1 means it is a GUID.");

static char *hostid = "";
module_param(hostid, charp, S_IRUGO);
MODULE_PARM_DESC(hostid,
		"A GUID which, if given, will be included in the output.");

static char *comment = "";
module_param(comment, charp, S_IRUGO);
MODULE_PARM_DESC(comment, "If given, will be included in the comment option "
		"of the section header block.  Spaces can be encoded as \\040 or \\x20.");

#ifndef CONFIG_HONE_DEFAULT_PAGEORDER
	#ifdef CONFIG_64BIT
		#define CONFIG_HONE_DEFAULT_PAGEORDER 3
	#else
		#define CONFIG_HONE_DEFAULT_PAGEORDER 2
	#endif
#endif

static unsigned int pageorder = CONFIG_HONE_DEFAULT_PAGEORDER;
module_param(pageorder, uint, S_IWUSR|S_IRUGO);
MODULE_PARM_DESC(pageorder,
		"Specifies the page order to use when allocating the ring buffer "
		"(default: " __stringify(CONFIG_HONE_DEFAULT_PAGEORDER) ").  The buffer "
		"size is computed as PAGE_SIZE * (1 << pageorder).");

static struct class *class_hone;

#define printm(level, fmt, ...) printk(level "%s: %s:%d: " fmt, mod_name, __FILE__, __LINE__, ##__VA_ARGS__)
#define mod_name (THIS_MODULE->name)

#define size_of_pages(order) (PAGE_SIZE << (order))
#define READ_BUFFER_PAGE_ORDER 5
#define READ_BUFFER_SIZE size_of_pages(READ_BUFFER_PAGE_ORDER)

#define READER_HEAD 0x00000001
#define READER_INIT 0x00000002
#define READER_TAIL 0x00000004
#define READER_FINISH 0x00000008
#define READER_RESTART 0x0000000F
#define READER_FILTER_PID 0x00000100

#define HASHTABLE_FLUSH_SECONDS 600

static struct device_info devinfo = {
	.comment = NULL,
	.host_id = NULL,
	.host_guid_is_set = false
};

struct hone_sock_filter {
	struct hlist_node node;
	uint32_t action;
	struct timespec next_log_time;
	struct sock_aggregate_event agg;
};

struct filter_work {
	struct work_struct ws;
	struct sock_argv param;
	struct hone_reader *reader;
	struct hone_sock_filter *filter;
};

static struct kmem_cache *work_cache;
static DEFINE_SPINLOCK(hone_sock_filter_lock);

static struct kmem_cache *hone_sock_filter_cache;

struct hone_reader {
	struct semaphore sem;
	struct ring_buf ringbuf;
	struct notifier_block nb;
	unsigned int (*format)(const struct device_info *,
		       struct reader_info *, struct hone_event *, char *, unsigned int);
	struct reader_info info;
	atomic_t flags, connected, aggregate_packet, aggregate_sec, next_flush_time;
	DECLARE_HASHTABLE(filter, 16);
	struct hone_event *event;
	wait_queue_head_t event_wait_queue;
	size_t length, offset;
	char *buf;
};

static struct hone_event head_event = {HONE_USER_HEAD, {ATOMIC_INIT(1)}};
static struct hone_event tail_event = {HONE_USER_TAIL, {ATOMIC_INIT(1)}};

#define reader_will_block(rdr) (ring_is_empty(&(rdr)->ringbuf) && \
		!(rdr)->event && !(atomic_read(&(rdr)->flags) & READER_RESTART))

static void inc_stats_counter(struct statistics *stats, int type)
{
	atomic64_t *counter;

	switch(type) {
	case HONE_PROCESS:
		counter = &stats->process;
		break;
	case HONE_SOCKET:
		counter = &stats->socket;
		break;
	case HONE_PACKET:
		counter = &stats->packet;
		break;
	case HONE_SOCKET_AGGREGATE:
		counter = &stats->aggregate;
		break;
	default:
		return;
	}
	atomic64_inc(counter);
}

static void inc_pending_work(struct hone_reader *reader)
{
	atomic64_inc(&reader->info.pending_work);
}

static void dec_pending_work(struct hone_reader *reader)
{
	BUG_ON(atomic64_dec_return(&reader->info.pending_work) == -1);
}

static void free_hone_sock_filter(struct hone_sock_filter *filter)
{
	if (!filter)
		return;
	hash_del(&filter->node);
	kmem_cache_free(hone_sock_filter_cache, filter);
}

/* Generate a new aggregate event and queue it be sent to userspace. */
static void enqueue_aggregate_event(struct hone_reader *reader,
				    struct hone_sock_filter *filter)
{
	struct hone_event *agg_event;

	agg_event = alloc_hone_event(HONE_SOCKET_AGGREGATE, GFP_ATOMIC);
	if (!agg_event) {
		inc_stats_counter(&reader->info.dropped, HONE_SOCKET_AGGREGATE);
		return;
	}

	agg_event->agg = filter->agg;
	if (ring_append(&reader->ringbuf, agg_event)) {
		inc_stats_counter(&reader->info.dropped, HONE_SOCKET_AGGREGATE);
		put_hone_event(agg_event);
		return;
	}
	inc_stats_counter(&reader->info.delivered, HONE_SOCKET_AGGREGATE);
	wake_up_interruptible_all(&reader->event_wait_queue);
}

/* Parse out the aggregate event from the packet event. */
static bool parse_sock_filter(struct hone_event *event, struct hone_sock_filter *filter)
{
	struct iphdr _iph, *iph;
	int iphdr_len = 0;

	if (!event || !filter)
		return false;
	if (event->type != HONE_PACKET)
		return false;
	memset(&filter->agg, 0, sizeof(filter->agg));
	filter->agg.sock = event->packet.sock;
	filter->agg.pid = event->packet.pid;

	iph = skb_header_pointer(event->packet.skb, 0, sizeof(_iph), &_iph);
	if (!iph)
		return false;
	filter->agg.ip_version = iph->version;
	// Parse out IP address from IPv4 header or IPv6 header.
	if (iph->version == 4) {
		filter->agg.saddr.in6_u.u6_addr16[5] = 0xFFFF;
		filter->agg.saddr.in6_u.u6_addr32[3] = iph->saddr;
		filter->agg.daddr.in6_u.u6_addr16[5] = 0xFFFF;
		filter->agg.daddr.in6_u.u6_addr32[3] = iph->daddr;
		filter->agg.protocol = iph->protocol;
		iphdr_len = iph->ihl * 4;
	} else if (iph->version == 6) {
		struct ipv6hdr _iph6, *iph6 = skb_header_pointer(
			event->packet.skb, 0, sizeof(_iph6), &_iph6);
		if (!iph6)
			return false;
		filter->agg.saddr = iph6->saddr;
		filter->agg.daddr = iph6->daddr;
		filter->agg.protocol = iph6->nexthdr;
		iphdr_len = sizeof(_iph6);
	} else {
		return false;
	}
	// Parse out port number from TCP header or UPD header.
	if (filter->agg.protocol == IPPROTO_TCP) {
		struct tcphdr _tcph, *tcph = skb_header_pointer(
			event->packet.skb, iphdr_len, sizeof(_tcph), &_tcph);
		if (!tcph)
			return false;
		filter->agg.source = ntohs(tcph->source);
		filter->agg.dest = ntohs(tcph->dest);
	} else if (filter->agg.protocol == IPPROTO_UDP) {
		struct udphdr _udph, *udph = skb_header_pointer(
			event->packet.skb, iphdr_len, sizeof(_udph), &_udph);
		if (!udph)
			return false;
		filter->agg.source = ntohs(udph->source);
		filter->agg.dest = ntohs(udph->dest);
	} else {
		return false;
	}
	if (event->packet.dir == PKTNOT_PACKET_IN) {
		filter->agg.pkts_in = 1;
		filter->agg.bytes_in = event->packet.skb->len;
	} else {
		filter->agg.pkts_out = 1;
		filter->agg.bytes_out = event->packet.skb->len;
	}
	filter->agg.start = filter->agg.end = event->ts;
	return true;
}

static void delayed_add_sock_filter(struct work_struct *work);

static struct hone_sock_filter *alloc_hone_sock_filter(
    struct sock_argv *sock_argv);

/*
 * Return true if event should be queued for userspace.
 *
 * For each packet,
 * 1. reader->aggregate_packet (which can be set from userland) is false:
 *    queue the packet (return true).
 * 2. reader->aggregate_packet is true: parses out netflow info, e.g. saddr,
 *    daddr, source, dest, the number of received/sent packets, the
 *    received/sent bytes, and so on. Then, put the netflow info into the work
 *    queue for the later aggregation.
 *    2.1. If source/dest port number is 53 (DNS), queue the packet.
 *    2.2. If not, not queue the packet.
 */
static bool enqueue_packet_event(struct hone_reader *reader,
				 struct hone_event *event)
{
	bool enqueue = true;
	// Aggregate packets in the kernel.
	if (atomic_read(&reader->aggregate_packet) > 0) {
		struct filter_work *work;
		work = kmem_cache_zalloc(work_cache, GFP_ATOMIC);
		if (!work)
			return false;
		work->param.sock = event->packet.sock;
		work->param.action = AGGREGATE;
		work->param.aggregate_sec = atomic_read(&reader->aggregate_sec);
		work->reader = reader;
		work->filter = alloc_hone_sock_filter(&work->param);
		if (!work->filter) {
			kmem_cache_free(work_cache, work);
			return false;
		}
		if (!parse_sock_filter(event, work->filter)) {
			kmem_cache_free(hone_sock_filter_cache, work->filter);
			kmem_cache_free(work_cache, work);
			return false;
		}
		// Queue the current packet if source/dest port number is 53.
		enqueue = (work->filter->agg.source == 53 || work->filter->agg.dest == 53);

		INIT_WORK((struct work_struct*) work, delayed_add_sock_filter);
		inc_pending_work(reader);
		BUG_ON(unlikely(!queue_work(hone_wq, (struct work_struct*) work)));
	}
	return enqueue;
}

/*
 * Allocate a new socket filter.
 */
static struct hone_sock_filter *alloc_hone_sock_filter(
    struct sock_argv *sock_argv)
{
	struct hone_sock_filter *filter = NULL;

	filter = kmem_cache_zalloc(hone_sock_filter_cache, GFP_ATOMIC);
	if (!filter)
		return NULL;

	filter->agg.sock = sock_argv->sock;
	filter->action = sock_argv->action;
	if (filter->action == AGGREGATE) {
		ktime_get_ts(&filter->next_log_time);
		filter->next_log_time.tv_sec += sock_argv->aggregate_sec;
	}
	return filter;
}

/*
 * Remove a socket from the filter list.
 */
static void delayed_free_sock_filter(struct work_struct *work)
{
	struct filter_work *w = (struct filter_work*) work;
	struct hone_sock_filter *filter;
	struct hlist_node *tmp;
	struct hone_reader *reader = w->reader;
	unsigned long flags;
	uint64_t sock = w->param.sock;

	if (atomic_read(&reader->connected) == 0) goto out;

	spin_lock_irqsave(&hone_sock_filter_lock, flags);
	hash_for_each_possible_safe(w->reader->filter, filter, tmp, node, sock) {
		if (filter->agg.sock == sock)
			free_hone_sock_filter(filter);
	}
	spin_unlock_irqrestore(&hone_sock_filter_lock, flags);
out:
	kmem_cache_free(work_cache, work);
	dec_pending_work(reader);
}

/*
 * Flush the aggregation info when its next_log_time exceeds the current time.
 */
static void flush_timeout_socks(struct hone_reader *reader) {
	struct hone_sock_filter *filter;
	int bkt;
	struct hlist_node *tmp = NULL;
	struct timespec cur_time;
	int cnt = 0, old_cnt = 0;

	ktime_get_ts(&cur_time);
	if (cur_time.tv_sec < atomic_read(&reader->next_flush_time))
		return;

	hash_for_each_safe(reader->filter, bkt, tmp, filter, node) {
		if (cur_time.tv_sec > filter->next_log_time.tv_sec) {
			old_cnt++;
			enqueue_aggregate_event(reader, filter);
			free_hone_sock_filter(filter);
		}
		cnt++;
	}
	atomic_set(&reader->next_flush_time,
	           cur_time.tv_sec + HASHTABLE_FLUSH_SECONDS);
}

/*
 * Add a socket to the filter list only if the socket isn't already
 * filtered.
 */
static void delayed_add_sock_filter(struct work_struct *work)
{
	struct filter_work *w = (struct filter_work*) work;
	struct hone_sock_filter *filter;
	struct hone_reader *reader = w->reader;
	unsigned long flags;

	if (!w->filter)
		goto out;
	if (atomic_read(&reader->connected) == 0) {
		kmem_cache_free(hone_sock_filter_cache, w->filter);
		goto out;
	}

	spin_lock_irqsave(&hone_sock_filter_lock, flags);
	hash_for_each_possible(w->reader->filter, filter, node, w->param.sock) {
		if (filter->agg.sock == w->param.sock) {
			if (w->param.action == IGNORE) {
				// Receive IGNORE from userland, and correct the action in the hashtable.
				filter->action = w->filter->action;
			} else if (filter->action == AGGREGATE) {
				atomic64_inc(&reader->info.aggregated);
				filter->agg.bytes_in += w->filter->agg.bytes_in;
				filter->agg.bytes_out += w->filter->agg.bytes_out;
				filter->agg.pkts_in += w->filter->agg.pkts_in;
				filter->agg.pkts_out += w->filter->agg.pkts_out;
				if (timespec_compare(&filter->agg.start, &w->filter->agg.start) > 0)
					filter->agg.start = w->filter->agg.start;
				if (timespec_compare(&filter->agg.end, &w->filter->agg.end) < 0)
					filter->agg.end = w->filter->agg.end;
				/* Now see if we need to log this event or if we need to continue
				 * aggregating */
				if (w->filter->agg.start.tv_sec >= filter->next_log_time.tv_sec) {
					// Enqueue the aggregate event and reset it.
					enqueue_aggregate_event(reader, filter);
					filter->agg.pkts_in = 0;
					filter->agg.pkts_out = 0;
					filter->agg.bytes_in = 0;
					filter->agg.bytes_out = 0;
				}
			} else if (filter->action == IGNORE) {
				atomic64_inc(&reader->info.filtered);
			} else {
				WARN_ONCE(true, "Invalid action (%d) on filter for sock 0x%lx\n",
				          filter->action, filter->agg.sock);
			}
			kmem_cache_free(hone_sock_filter_cache, w->filter);
			w->filter = NULL;
			spin_unlock_irqrestore(&hone_sock_filter_lock, flags);
			goto out;
		}
	}

	hash_add(w->reader->filter, &w->filter->node, w->filter->agg.sock);
	w->filter = NULL;
	flush_timeout_socks(reader);
	spin_unlock_irqrestore(&hone_sock_filter_lock, flags);
out:
	kmem_cache_free(work_cache, work);
	dec_pending_work(reader);
}

/* Send a new aggregation event to userspace. */
static void delay_add_sock_close_agg_event(struct work_struct *work)
{
	struct filter_work *w = (struct filter_work*) work;
	struct hlist_node *tmp;
	struct hone_sock_filter *filter;
	struct hone_reader *reader = w->reader;
	unsigned long flags;

	if (atomic_read(&reader->connected) == 0) goto out;

	spin_lock_irqsave(&hone_sock_filter_lock, flags);
	hash_for_each_possible_safe(w->reader->filter, filter, tmp, node, w->param.sock) {
		if (filter->agg.sock == w->param.sock) {
			if (filter->action == AGGREGATE)
				enqueue_aggregate_event(reader, filter);
			free_hone_sock_filter(filter);
		}
	}
	spin_unlock_irqrestore(&hone_sock_filter_lock, flags);

out:
	kmem_cache_free(work_cache, work);
	dec_pending_work(reader);
}

/* If we're aggregating on this socket and it's just been closed, we need
   to put into workqueue to send a new aggregate event to userspace in addition
   to the regular socket close message */
static void add_sock_close_agg_event(struct hone_reader *reader,
				     struct hone_event *event)
{
	struct filter_work *work;

	work = kmem_cache_zalloc(work_cache, GFP_ATOMIC);
	if (!work) {
		pr_err("couldn't alloc filter, losing stats on 0x%lx\n",
		       event->socket.sock);
		return;
	}

	work->param.sock = event->socket.sock;
	work->filter = NULL;
	work->reader = reader;

	INIT_WORK((struct work_struct*)work, delay_add_sock_close_agg_event);
	BUG_ON(unlikely(!queue_work(hone_wq, (struct work_struct*) work)));
	inc_pending_work(reader);
}

/* Return true if this event should be sent to userspace. */
static bool inline enqueue_event(struct hone_reader *reader,
		struct hone_event *event)
{
	/* Ignore threads for now */
	if (event->type == HONE_PROCESS && event->process.pid != event->process.tgid)
		return false;

	/* Ignore packets sent or received on sockets that userland has told
	   us to ignore. */
	if (event->type == HONE_PACKET &&
	    enqueue_packet_event(reader, event) != true)
		return false;

	if (event->type == HONE_SOCKET && event->socket.event != 0)
		add_sock_close_agg_event(reader, event);

	get_hone_event(event);
	if (ring_append(&reader->ringbuf, event)) {
		inc_stats_counter(&reader->info.dropped, event->type);
		put_hone_event(event);
		return false;
	}
	/* This event should be sent to userspace. */
	return true;
}

static int hone_event_handler(struct notifier_block *nb, unsigned long val, void *v)
{
	struct hone_reader *reader = container_of(nb, struct hone_reader, nb);

	if (enqueue_event(reader, v))
		wake_up_interruptible_all(&reader->event_wait_queue);

	return 0;
}

static void free_hone_reader(struct hone_reader *reader)
{
	if (reader) {
		if (reader->ringbuf.data) {
			free_pages((unsigned long) (reader->ringbuf.data), reader->ringbuf.pageorder);
			reader->ringbuf.data = NULL;
		}
		if (reader->buf) {
			free_pages((unsigned long) (reader->buf), READ_BUFFER_PAGE_ORDER);
			reader->buf = NULL;
		}
		kfree(reader);
	}
}

static struct hone_reader *alloc_hone_reader(void)
{
	struct hone_reader *reader;
	struct ring_buf *ring;

	if (!(reader = kzalloc(sizeof(*reader), GFP_KERNEL)))
		goto alloc_failed;
	if (!(reader->buf = (typeof(reader->buf))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, READ_BUFFER_PAGE_ORDER)))
		goto alloc_failed;
	ring = &reader->ringbuf;
	ring->pageorder = pageorder;
	if (!(ring->data = (typeof(ring->data))
				__get_free_pages(GFP_KERNEL | __GFP_ZERO, ring->pageorder)))
		goto alloc_failed;
	ring->length = size_of_pages(ring->pageorder) / sizeof(*(ring->data));
	reader->format = format_as_pcapng;
	atomic_set(&reader->flags, READER_HEAD | READER_INIT);
	sema_init(&reader->sem, 1);
	init_waitqueue_head(&reader->event_wait_queue);
	return reader;

alloc_failed:
	free_hone_reader(reader);
	return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#define OPEN_FDS open_fds
#else
#define OPEN_FDS open_fds->fds_bits
#endif

/*
 * This is identical to get_files_struct() in fs/file.c but that function isn't
 * exported so it can't be used in a kernel module.
 */
struct files_struct *hone_get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
}

static struct hone_event *__add_files(struct hone_reader *reader,
		struct hone_event *event, struct task_struct *task)
{
	struct hone_event *sk_event;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	struct socket *sock;
	struct sock *sk;
	unsigned long flags, set;
	int i, fd, err;

	if (!(files = hone_get_files_struct(task)))
		return event;
	spin_lock_irqsave(&files->file_lock, flags);
	if (!(fdt = files_fdtable(files)))
		goto out;
	for (i = 0; (fd = i * BITS_PER_LONG) < fdt->max_fds; i++) {
		for (set = fdt->OPEN_FDS[i]; set; set >>= 1, fd++) {
			if (!(set & 1))
				continue;
			file = fdt->fd[fd];
			if (!file)
				continue;
			if (!(sock = sock_from_file(file, &err)))
				continue;
			sk = sock->sk;
			if (!sk || (sk->sk_family != PF_INET && sk->sk_family != PF_INET6))
				continue;
			sk->sk_protinfo = (void*)(unsigned long)
					(task->pid == task->tgid ? task->pid : task->tgid);
			if ((sk_event = __alloc_socket_event((unsigned long) sk,
							     0, task, GFP_ATOMIC))) {
				sk_event->next = event;
				event = sk_event;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
				event->ts.tv_sec = (task->start_time / 1000000000);
				event->ts.tv_nsec = (task->start_time % 1000000000);
#else
				event->ts = task->start_time;
#endif
			} else {
				atomic64_inc(&reader->info.dropped.socket);
			}
		}
	}
out:
	spin_unlock_irqrestore(&files->file_lock, flags);
	put_files_struct(files);
	return event;
}


#define prev_task(p) \
	list_entry_rcu((p)->tasks.prev, struct task_struct, tasks)

static struct hone_event *add_current_tasks(
		struct hone_reader *reader, struct hone_event *event)
{
	struct hone_event *proc_event;
	struct task_struct *task;

	rcu_read_lock();
	for (task = &init_task; (task = prev_task(task)) != &init_task; ) {
		struct process_args pargs = { .task = task };
		if (task->flags & PF_EXITING)
			continue;
		event = __add_files(reader, event, task);
		if ((proc_event = __alloc_process_event(&pargs,
						task->flags & PF_FORKNOEXEC ? PROC_FORK : PROC_EXEC,
						GFP_ATOMIC))) {
			proc_event->next = event;
			event = proc_event;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
			event->ts.tv_sec = (task->start_time / 1000000000);
			event->ts.tv_nsec = (task->start_time % 1000000000);
#else
			event->ts = task->start_time;
#endif
		} else {
			atomic64_inc(&reader->info.dropped.process);
		}
	}
	rcu_read_unlock();
	return event;
}

static void free_initial_events(struct hone_reader *reader)
{
	struct hone_event *event, *next;

	for (event = reader->event; event; event = next) {
		next = event->next;
		free_hone_event(event);
	}
	reader->event = NULL;
}

static void add_initial_events(struct hone_reader *reader)
{
	free_initial_events(reader);
	reader->event = add_current_tasks(reader, NULL);
}

static int hone_open(struct inode *inode, struct file *file)
{
	struct hone_reader *reader = NULL;
	int err = -ENOMEM;

	if ((file->f_flags & O_ACCMODE) != O_RDONLY)
		return -EINVAL;
	if (!(reader = alloc_hone_reader()))
		goto reader_failed;
	file->private_data = reader;
	getboottime(&reader->info.boot_time);
	ktime_get_ts(&reader->info.start_time);
	atomic64_set(&reader->info.filtered, 0);
	atomic64_set(&reader->info.aggregated, 0);
	atomic64_set(&reader->info.ioctl, 0);
	atomic64_set(&reader->info.pending_work, 0);
	atomic_set(&reader->connected, 1);
	atomic_set(&reader->aggregate_packet, 1);
	atomic_set(&reader->aggregate_sec, 300);
	atomic_set(&reader->next_flush_time,
	           reader->info.start_time.tv_sec + HASHTABLE_FLUSH_SECONDS);
	init_statistics(&reader->info.delivered);
	init_statistics(&reader->info.dropped);
	reader->nb.notifier_call = hone_event_handler;
	if ((err = hone_notifier_register(&reader->nb))) {
		printm(KERN_ERR, "hone_notifier_register() failed with error %d\n", err);
		goto register_failed;
	}
	__module_get(THIS_MODULE);

	return 0;

register_failed:
	free_hone_reader(reader);
reader_failed:
	return err;
}

static int hone_release(struct inode *inode, struct file *file)
{
	struct hone_reader *reader = file->private_data;
	struct hone_event *event = NULL;

	if (hone_notifier_unregister(&reader->nb) < 0) return -EINTR;

	atomic_set(&reader->connected, 0);
	while (atomic64_read(&reader->info.pending_work) > 0)
		msleep(1);

	file->private_data = NULL;

	while ((event = ring_pop(&reader->ringbuf)))
		put_hone_event(event);

	if (reader->filter) {
		struct hone_sock_filter *filter = NULL;
		struct hlist_node *tmp = NULL;
		int bkt;
		unsigned long flags;

		spin_lock_irqsave(&hone_sock_filter_lock, flags);
		hash_for_each_safe(reader->filter, bkt, tmp, filter, node) {
			free_hone_sock_filter(filter);
		}
		spin_unlock_irqrestore(&hone_sock_filter_lock, flags);
	}

	free_initial_events(reader);
	free_hone_reader(reader);
	module_put(THIS_MODULE);

	return 0;
}

static ssize_t hone_read(struct file *filp, char __user *buffer,
		size_t length, loff_t *offset)
{
	struct hone_reader *reader = filp->private_data;
	size_t n, copied = 0;

	if (!length)
		return 0;

	do {
		while (!reader->offset && reader_will_block(reader)) {
			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			if (wait_event_interruptible(reader->event_wait_queue,
						!reader_will_block(reader)))
				return -EINTR;
		}

		if (filp->f_flags & O_NONBLOCK) {
			if (down_trylock(&reader->sem))
				return -EAGAIN;
		} else if (down_interruptible(&reader->sem)) {
			return -EINTR;
		}

		while (copied < length) {
			if (!reader->offset) {
				int flags = 0;
				struct hone_event *event = NULL;
				void (*free_event)(struct hone_event *);

				flags = atomic_read(&reader->flags);
				if (flags & READER_TAIL) {
					atomic_clear_mask(READER_TAIL, &reader->flags);
					event = &tail_event;
					free_event = NULL;
				} else if (flags & READER_FINISH) {
					if (!copied)
						atomic_clear_mask(READER_FINISH, &reader->flags);
					up(&reader->sem);
					return copied;
				} else if (flags & READER_HEAD) {
					atomic_clear_mask(READER_HEAD, &reader->flags);
					event = &head_event;
					free_event = NULL;
				} else if (flags & READER_INIT) {
					atomic_clear_mask(READER_INIT, &reader->flags);
					add_initial_events(reader);
					continue;
				} else if (reader->event) {
					if ((event = reader->event))
						reader->event = event->next;
					free_event = free_hone_event;
				} else {
					event = ring_pop(&reader->ringbuf);
					free_event = put_hone_event;
				}

				if (!event) break;
				reader->length = reader->format(&devinfo, &reader->info,
						event, reader->buf, READ_BUFFER_SIZE);
				inc_stats_counter(&reader->info.delivered, event->type);
				if (free_event)
					free_event(event);
			}
			n = min(reader->length - reader->offset, length - copied);
			if (copy_to_user(buffer + copied, reader->buf + reader->offset, n)) {
				up(&reader->sem);
				return -EFAULT;
			}
			copied += n;
			reader->offset += n;
			if (reader->offset >= reader->length)
				reader->offset = 0;
		}
		up(&reader->sem);
	} while (!copied);  // loop until at least some data has been copied.
	return copied;
}

extern void fput(struct file *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static long hone_ioctl(struct file *file, unsigned int num,
		unsigned long param)
#else
static int hone_ioctl(struct inode *inode, struct file *file,
		unsigned int num, unsigned long param)
#endif
{
	struct hone_reader *reader = file->private_data;

	if (_IOC_TYPE(num) != 0xE0)
		return -EINVAL;

	atomic64_inc(&reader->info.ioctl);

	switch (num) {
	case HEIO_RESTART:
		atomic_set_mask(READER_RESTART, &reader->flags);
		wake_up_interruptible_all(&reader->event_wait_queue);
		return 0;
	case HEIO_GET_AT_HEAD:
		return atomic_read(&reader->flags) & READER_HEAD ? 1 : 0;
	case HEIO_GET_SNAPLEN:
		return put_user(reader->info.snaplen, (unsigned int __user *) param);
	case HEIO_SET_SNAPLEN:
		reader->info.snaplen = (unsigned int) param;
		atomic_set_mask(READER_HEAD, &reader->flags);
		return 0;
	case HEIO_STATS:
		atomic_set_mask(READER_TAIL, &reader->flags);
		return 0;
	case HEIO_SOCK_FILTER:
	{
		struct sock_argv sock_param;
		struct filter_work *work;

		if (copy_from_user(&sock_param, (struct sock_argv*)param,
				   sizeof(struct sock_argv)))
			return -EINVAL;

		switch (sock_param.action) {
		case IGNORE:
			work = kmem_cache_zalloc(work_cache, GFP_ATOMIC);
			if (!work)
				return -EAGAIN;

			work->param.sock = sock_param.sock;
			work->param.action = sock_param.action;
			work->param.aggregate_sec = sock_param.aggregate_sec;
			work->reader = reader;
			work->filter = alloc_hone_sock_filter(&sock_param);
			if (!work->filter) {
				kmem_cache_free(work_cache, work);
				return -EINVAL;
			}

			INIT_WORK((struct work_struct*) work, delayed_add_sock_filter);
			inc_pending_work(reader);
			BUG_ON(unlikely(!queue_work(hone_wq, (struct work_struct*) work)));
			return 0;
		case AGGREGATE:
			printk(KERN_WARNING "Not support AGGREGATE command and no effect.");
			return 0;
		case REMOVE:
			work = kmem_cache_zalloc(work_cache, GFP_ATOMIC);
			if (!work)
				return -EAGAIN;

			work->param.sock = sock_param.sock;
			work->reader = reader;
			work->filter = NULL;

			INIT_WORK((struct work_struct*) work, delayed_free_sock_filter);
			inc_pending_work(reader);
			BUG_ON(unlikely(!queue_work(hone_wq, (struct work_struct*) work)));
			return 0;
		case ENABLE_AGGREGATE:
			atomic_set(&reader->aggregate_packet, 1);
			atomic_set(&reader->aggregate_sec, sock_param.aggregate_sec);
			return 0;
		case DISABLE_AGGREGATE:
			atomic_set(&reader->aggregate_packet, 0);
			atomic_set(&reader->aggregate_sec, 0);
			return 0;
		}
		return 0;
	}
	}
	return -EINVAL;
}

static unsigned int hone_poll(struct file *file,
		struct poll_table_struct *wait)
{
	struct hone_reader *reader = file->private_data;

	poll_wait(file, &reader->event_wait_queue, wait);
	if (!reader_will_block(reader))
		return POLLIN | POLLRDNORM;
	return 0;
}

static const struct file_operations device_ops = {
	.read = hone_read,
	.open = hone_open,
	.release = hone_release,
	.unlocked_ioctl = hone_ioctl,
	.compat_ioctl = hone_ioctl,
	.poll = hone_poll,
};

#ifdef CONFIG_HONE_NOTIFY_COMBINED
	int hone_notify_init(void) __init;
	void hone_notify_release(void);
#else
#	define hone_notify_init() (0)
#	define hone_notify_release()
#endif

static int __init honeevent_init(void)
{
	int err;

	if (hostid && *hostid) {
		if (!hostid_type)
			devinfo.host_id = hostid;
		else if (hostid_type == 1) {
			if (parse_guid(&devinfo.host_guid, hostid)) {
				printm(KERN_ERR, "invalid host GUID: %s\n", hostid);
				return -1;
			}
			printm(KERN_DEBUG, "using host GUID {" GUID_FMT "}\n",
					GUID_TUPLE(&devinfo.host_guid));
			devinfo.host_guid_is_set = true;
		} else {
			printm(KERN_ERR, "invalid hostid_type: %d\n", hostid_type);
			return -1;
		}
	}
	if (comment && *comment)
		devinfo.comment = comment;

	err = -1;
	if (hone_notify_init() != 0)
		goto hone_init_fail;

	hone_sock_filter_cache = kmem_cache_create("hone_sock_filter",
						   sizeof(struct hone_sock_filter),
						   0, 0, NULL);
	if (!hone_sock_filter_cache) {
		pr_err("couldn't alloc filter cache\n");
		goto filter_cache_fail;
	}
	work_cache = kmem_cache_create("hone_work_cache",
				       sizeof(struct filter_work), 0, 0, NULL);
	if (!work_cache) {
		pr_err("couldn't alloc work cache\n");
		goto work_cache_fail;
	}

	if ((err = register_chrdev(major, devname, &device_ops)) < 0) {
		printm(KERN_ERR, "character device registration returned error %d\n", err);
		goto chrdev_fail;
	}
	if (!major)
		major = err;

	class_hone = class_create(THIS_MODULE, devname);
	if (IS_ERR(class_hone)) {
		printm(KERN_ERR, "class_create failed\n");
		err = PTR_ERR(class_hone);
		goto class_fail;
	}

	device_create(class_hone, NULL, MKDEV(major, 0), NULL, "%s", devname);

	printk(KERN_INFO "%s: v%s module successfully loaded with major number %d\n",
			mod_name, version, major);
	return 0;

class_fail:
	unregister_chrdev(major, devname);
chrdev_fail:
	kmem_cache_destroy(work_cache);
work_cache_fail:
	kmem_cache_destroy(hone_sock_filter_cache);
filter_cache_fail:
	hone_notify_release();
hone_init_fail:
	return err;
}

static void __exit honeevent_exit(void)
{
	device_destroy(class_hone, MKDEV(major, 0));
	class_destroy(class_hone);
	unregister_chrdev(major, devname);
	hone_notify_release();
	kmem_cache_destroy(hone_sock_filter_cache);
	kmem_cache_destroy(work_cache);
	printk(KERN_INFO "%s: module successfully unloaded\n", mod_name);
}

module_init(honeevent_init);
module_exit(honeevent_exit);
