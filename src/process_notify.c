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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/notifier.h>

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#if !defined(CONFIG_KPROBES) || !defined(CONFIG_KRETPROBES) || !defined(CONFIG_KALLSYMS)
#error process_notify module requires kprobes support (CONFIG_KPROBES, CONFIG_KRETPROBES and CONFIG_KALLSYMS)
#endif

#include "process_notify.h"
#include "version.h"

static ATOMIC_NOTIFIER_HEAD(notifier_list);

int process_notifier_register(struct notifier_block *nb)
{
	return atomic_notifier_chain_register(&notifier_list, nb);
}

int process_notifier_unregister(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&notifier_list, nb);
}

static inline int process_notifier_notify(unsigned long event,
					  struct process_args *pargs)
{
	return atomic_notifier_call_chain(&notifier_list, event, pargs);
}

static int fork_handler(struct task_struct *tsk)
{
	struct process_args pargs = { .task = tsk };

	if (likely(!IS_ERR(tsk)))
		process_notifier_notify(PROC_FORK, &pargs);
	jprobe_return();
	return 0;
}

static int exec_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	if (!(int) regs_return_value(regs)) {
		struct process_args pargs = { .task = current };
		process_notifier_notify(PROC_EXEC, &pargs);
	}
	return 0;
}

static int exit_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct process_args pargs = { .task = current };

#ifdef CONFIG_X86_64
	pargs.code = (int)regs->di;
#endif
	process_notifier_notify(PROC_EXIT, &pargs);
	return 0;
}

static struct jprobe fork_jprobe = {
	.kp.symbol_name = "wake_up_new_task",
	.entry = fork_handler,
};

static struct kretprobe exec_kretprobe = {
	.kp.symbol_name = "sys_execve",
	.handler = exec_handler,
};

#ifdef CONFIG_COMPAT
static struct kretprobe compat_exec_kretprobe = {
	.kp.symbol_name = "compat_sys_execve",
	.handler = exec_handler,
};
#endif

static struct kprobe exit_kprobe = {
	.addr = (kprobe_opcode_t *) do_exit,
	.pre_handler = exit_handler,
};

#ifdef CONFIG_PROCESS_NOTIFY_COMBINED
#  define _STATIC
#else
#  define _STATIC static
#endif

_STATIC int __init process_notify_init(void)
{
	int err;

	if ((err = register_kprobe(&exit_kprobe))) {
		printk(KERN_ERR "%s: exit register_kprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto exit_failed;
	}
	if ((err = register_jprobe(&fork_jprobe))) {
		printk(KERN_ERR "%s: fork register_jprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto fork_failed;
	}
	if ((err = register_kretprobe(&exec_kretprobe))) {
		printk(KERN_ERR "%s: exec register_kretprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		goto exec_failed;
	}
#ifdef CONFIG_COMPAT
	if ((err = register_kretprobe(&compat_exec_kretprobe))) {
		printk(KERN_ERR "%s: compat_exec register_kretprobe() failed with error %d\n",
				THIS_MODULE->name, err);
		if (err != -EINVAL)
			goto compat_exec_failed;
	}
#endif
	return 0;

#ifdef CONFIG_COMPAT
compat_exec_failed:
	unregister_kretprobe(&exec_kretprobe);
#endif
exec_failed:
	unregister_jprobe(&fork_jprobe);
fork_failed:
	unregister_kprobe(&exit_kprobe);
exit_failed:
	return err;
}

_STATIC void process_notify_remove(void)
{
#ifdef CONFIG_COMPAT
	unregister_kretprobe(&compat_exec_kretprobe);
#endif
	unregister_kretprobe(&exec_kretprobe);
	unregister_jprobe(&fork_jprobe);
	unregister_kprobe(&exit_kprobe);
}

#ifndef CONFIG_PROCESS_NOTIFY_COMBINED

static char version[] __initdata = HONE_VERSION;

static int __init process_notify_module_init(void)
{
	if (process_notify_init())
		return -1;
	printk("%s: v%s module successfully loaded\n", THIS_MODULE->name, version);
	return 0;
}

static void __exit process_notify_module_exit(void)
{
	process_notify_remove();
	printk("%s: module successfully unloaded\n", THIS_MODULE->name);
}

module_init(process_notify_module_init);
module_exit(process_notify_module_exit);

MODULE_DESCRIPTION("Process event notification module.");
MODULE_AUTHOR("Brandon Carpenter");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(HONE_VERSION);

EXPORT_SYMBOL(process_notifier_register);
EXPORT_SYMBOL(process_notifier_unregister);

#endif // CONFIG_PROCESS_NOTIFY_COMBINED
