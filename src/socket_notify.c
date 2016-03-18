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

#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/notifier.h>

#include <linux/in.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/inet_common.h>

#include "socket_notify.h"
#include "version.h"

#if !defined(CONFIG_IPV6) && defined(CONFIG_IPV6_MODULE)
#warning Hone does not support IPv6 when it is built as a module.
#warning Hone will not provide IPv6 packet/process correlation.
#endif

static ATOMIC_NOTIFIER_HEAD(notifier_list);

#ifndef rcu_dereference_raw
#define notifier_call_chain_empty() (rcu_dereference(notifier_list.head) == NULL)
#else
#define notifier_call_chain_empty() (rcu_dereference_raw(notifier_list.head) == NULL)
#endif

int sock_notifier_register(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&notifier_list, nb);
}

int sock_notifier_unregister(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&notifier_list, nb);
}

static inline int sock_notifier_notify(unsigned long event, struct sock *sk)
{
	return atomic_notifier_call_chain(&notifier_list, event, sk);
}

void inet_sock_destruct_handler(struct sock *sk)
{
	sock_notifier_notify(0xFFFFFFFF, sk);
	jprobe_return();
}

static inline void _finish_hook(struct sock *sk)
{
	if (notifier_call_chain_empty())
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	BUG_ON(unlikely(sk->sk_protinfo));
	sk->sk_protinfo = (void *) (unsigned long)
			(current->pid == current->tgid ? current->pid : current->tgid);
#endif
	sock_notifier_notify(0, sk);
}

static int sock_sendmsg_handler(struct kprobe *p, struct pt_regs *regs) {
#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	struct socket *sock = (struct socket*)regs->di;

	if (unlikely(!sock) || unlikely(!sock->sk))
		goto out;

	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		if (unlikely((unsigned long)sock->sk->sk_protinfo !=
				current->pid)) {
			sock->sk->sk_protinfo = (void*)(unsigned long)
					current->pid;
		}
	}
out:
#endif
	return 0;
}

static int sock_recvmsg_handler(struct kprobe *p, struct pt_regs *regs) {
#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	struct socket *sock = (struct socket*)regs->di;

	if (unlikely(!sock) || unlikely(!sock->sk))
		goto out;

	switch (sock->sk->sk_family) {
	case PF_INET:
	case PF_INET6:
		if (unlikely((unsigned long)sock->sk->sk_protinfo !=
				current->pid)) {
			sock->sk->sk_protinfo = (void*)(unsigned long)
					current->pid;
		}
	}
out:
#endif
	return 0;
}

struct retprobe_save {
	struct socket *sock;
};

static int inet_create_retprobe_entry(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	struct retprobe_save *s;
	s = (struct retprobe_save*)ri->data;
#ifdef CONFIG_X86_64
	s->sock = (struct socket*)regs->si;
#else
	s->sock = NULL;
#endif
	return 0;
}

static int inet_create_retprobe(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (regs_return_value(regs) == 0 && ri->data != NULL) {
		struct retprobe_save *s = (struct retprobe_save*)ri->data;
		_finish_hook(s->sock->sk);
	}
	return 0;
}

static struct kretprobe inet_create_probe = {
	.handler = inet_create_retprobe,
	.entry_handler = inet_create_retprobe_entry,
	.data_size = sizeof(struct retprobe_save),
	.kp.symbol_name = "inet_create",
};

#if defined(CONFIG_IPV6)
static struct kretprobe inet6_create_probe = {
	.handler = inet_create_retprobe,
	.entry_handler = inet_create_retprobe_entry,
	.data_size = sizeof(struct retprobe_save),
	.kp.symbol_name = "inet6_create",
};
#endif

static struct kretprobe *inet_create_probes[] = {
	&inet_create_probe,
#if defined(CONFIG_IPV6)
	&inet6_create_probe,
#endif
};

static struct jprobe inet_sock_destruct_jprobe = {
	.kp.symbol_name = "inet_sock_destruct",
	.entry = inet_sock_destruct_handler,
};

static struct kprobe sock_sendmsg_kprobe = {
	.addr = (kprobe_opcode_t*) sock_sendmsg,
	.pre_handler = sock_sendmsg_handler,
};

static struct kprobe sock_recvmsg_kprobe = {
	.addr = (kprobe_opcode_t*) sock_recvmsg,
	.pre_handler = sock_recvmsg_handler,
};

static struct kprobe *socket_msg_probes[] = {
	&sock_sendmsg_kprobe,
	&sock_recvmsg_kprobe,
};

#ifdef CONFIG_SOCKET_NOTIFY_COMBINED
#  define _STATIC
#else
#  define _STATIC static
#endif

_STATIC int __init socket_notify_init(void)
{
	int err;
	if ((err = register_kretprobes(inet_create_probes,
				       ARRAY_SIZE(inet_create_probes)))) {
		pr_err("error register inet_create probes\n");
		return err;
	}
	if ((err = register_kprobes(socket_msg_probes,
				    ARRAY_SIZE(socket_msg_probes)))) {
		pr_err("error registering socket_msg probes\n");
		unregister_kretprobes(inet_create_probes,
				      ARRAY_SIZE(inet_create_probes));
		return err;
	}
	if ((err = register_jprobe(&inet_sock_destruct_jprobe)) < 0) {
		printk(KERN_ERR "error registering inet_sock_destruct_jprobe\n");
		unregister_kretprobes(inet_create_probes,
				      ARRAY_SIZE(inet_create_probes));
		unregister_kprobes(socket_msg_probes,
				   ARRAY_SIZE(socket_msg_probes));
		return err;
	}
	return 0;
}

_STATIC void socket_notify_remove(void)
{
	unregister_jprobe(&inet_sock_destruct_jprobe);
	unregister_kprobes(socket_msg_probes, ARRAY_SIZE(socket_msg_probes));
	unregister_kretprobes(inet_create_probes,
			      ARRAY_SIZE(inet_create_probes));
	synchronize_net();
}

#ifndef CONFIG_SOCKET_NOTIFY_COMBINED

static char version[] __initdata = HONE_VERSION;

static int __init socket_notify_module_init(void)
{
	if (socket_notify_init())
		return -1;
	printk("%s: v%s module successfully loaded\n", THIS_MODULE->name, version);
	return 0;
}

static void __exit socket_notify_module_exit(void)
{
	socket_notify_remove();
	printk("%s: module successfully unloaded\n", THIS_MODULE->name);
}

module_init(socket_notify_module_init);
module_exit(socket_notify_module_exit);

MODULE_DESCRIPTION("Socket event notification module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HONE_VERSION);

EXPORT_SYMBOL(sock_notifier_register);
EXPORT_SYMBOL(sock_notifier_unregister);

#endif // CONFIG_SOCKET_NOTIFY_COMBINED
