/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/kallsyms.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/umh.h>
#include <linux/uaccess.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#include "u2k_thread.h"

struct u2k_thread {
	struct kref ref;
	struct subprocess_info *info;
	int stop;
	struct completion exited;
	struct task_struct *task;
	char *argv[5];
	char arg1[20];
	char arg2[20];
	char arg3[20];
};

static int u2k_open(struct inode *i, struct file *f)
{
	//printk(KERN_INFO "Driver: open()\n");
	return 0;
}
static int u2k_close(struct inode *i, struct file *f)
{
	//printk(KERN_INFO "Driver: close()\n");
	return 0;
}
static ssize_t u2k_read(struct file *f, char __user *buf, size_t
  len, loff_t *off)
{
	//printk(KERN_INFO "Driver: read()\n");
	return 0;
}

static ssize_t u2k_write(struct file *f, const char __user *buf,
  size_t len, loff_t *off)
{
	//printk(KERN_INFO "Driver: write()\n");
	return len;
}

static long u2k_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -ENOTSUPP;
	
	switch (cmd) {
	case IOC_CMD_RUN_THREAD: {
		struct thread_args args;
		void (*entry)(void*, void*);
		struct u2k_thread *thread;
		
		if (copy_from_user(&args, (void*)arg, sizeof(args)) != 0)
			return -EINVAL;
		if (!args.entry || !args.thread)
			return -EINVAL;

		pr_info("u2k: start %lx(%lx, %lx)\n", (unsigned long)args.entry, (unsigned long)args.arg, (unsigned long)args.thread);

		/* get task struct */
		thread = (void*)(unsigned long)args.thread;
		thread->task = get_task_struct(current);
		
		entry = (void*)(unsigned long)args.entry;
		entry((void*)(unsigned long)args.arg, thread);

		/* mark thread completion */
		complete(&thread->exited);
		
		pr_info("u2k: end %lx(%lx, %lx)\n", (unsigned long)args.entry, (unsigned long)args.arg, (unsigned long)args.thread);
		return 0;
	} break;

	default:
		break;
	}
	
	return ret;
}

static struct file_operations g_u2k_fops = {
	.owner = THIS_MODULE,
	.open = u2k_open,
	.release = u2k_close,
	.read = u2k_read,
	.write = u2k_write,
	.unlocked_ioctl = u2k_ioctl,
};

static dev_t g_u2k_devid;
static struct cdev g_u2k_cdev;
static struct class *g_u2k_class;

int u2k_init_chrdev(void)
{
	int result;

	result = alloc_chrdev_region(&g_u2k_devid, 0, 1, U2K_DEVNAME);
	if (result)
		return result;

	g_u2k_class = class_create(THIS_MODULE, U2K_DEVNAME);
	if (IS_ERR(g_u2k_class)) {
		result = PTR_ERR(g_u2k_class);
		goto l_unregister_chrdev;
	}

	if (device_create(g_u2k_class, NULL, g_u2k_devid, NULL, U2K_DEVNAME) == NULL) {
		result = -1;
		goto l_destroy_class;
	}
	 
	cdev_init(&g_u2k_cdev, &g_u2k_fops);
	result = cdev_add(&g_u2k_cdev, g_u2k_devid, 1);
	if (result)
		goto l_device_destroy;

	return 0;
	
l_device_destroy:
	device_destroy(g_u2k_class, g_u2k_devid);
l_destroy_class:
	class_destroy(g_u2k_class);		
l_unregister_chrdev:
	unregister_chrdev_region(g_u2k_devid, 1);
	return result;
}

void u2k_uninit_chrdev(void)
{
	cdev_del(&g_u2k_cdev);
	device_destroy(g_u2k_class, g_u2k_devid);
	class_destroy(g_u2k_class);
	unregister_chrdev_region(g_u2k_devid, 1);
}

static void u2k_thread_release(struct kref *ref)
{
	struct u2k_thread *thread = container_of(ref, struct u2k_thread, ref);

	pr_info("release thread %lx\n", (long)thread);
	kfree(thread);
}

static void free_u2k_argv(struct subprocess_info *info)
{
	struct u2k_thread *thread = info->data;
	
	kref_put(&thread->ref, u2k_thread_release);
}

char u2k_bin_path[] = "/usr/bin/u2k";

struct u2k_thread *u2k_thread_run(unsigned long entry, unsigned long args)
{
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};
	int ret;
	
	struct u2k_thread *thread = kmalloc(sizeof(struct u2k_thread), GFP_KERNEL);
	if (!thread)
		return NULL;
	kref_init(&thread->ref);
	init_completion(&thread->exited);
	thread->task = NULL;
	thread->stop = 0;
	thread->argv[0] = u2k_bin_path;
	thread->argv[1] = thread->arg1;
	thread->argv[2] = thread->arg2;
	thread->argv[3] = thread->arg3;
	thread->argv[4] = NULL;
	sprintf(thread->argv[1], "%lx", entry);
	sprintf(thread->argv[2], "%lx", args);
	sprintf(thread->argv[3], "%lx", (unsigned long)thread);
	thread->info = call_usermodehelper_setup(u2k_bin_path, thread->argv, envp, GFP_KERNEL,
					 NULL, free_u2k_argv, thread);
	if (!thread->info) {
		kfree(thread);
		return NULL;
	}
	pr_info("u2k: call %s %s %s %s\n", thread->argv[0], thread->argv[1], thread->argv[2], thread->argv[3]);
	kref_get(&thread->ref);
	ret = call_usermodehelper_exec(thread->info, UMH_WAIT_EXEC);
	if (ret < 0) {
		pr_warn("call_usermodehelper_exec.ret = %d\n", ret);
		kfree(thread);
		return NULL;
	}
	return thread;
}

int u2k_thread_stop(struct u2k_thread *thread)
{
	thread->stop = 1;
	if (thread->task) {
		wake_up_process(thread->task);
		wait_for_completion(&thread->exited);
		put_task_struct(thread->task);
	}
	kref_put(&thread->ref, u2k_thread_release);
	return 0;
}

bool u2k_thread_should_stop(struct u2k_thread *thread)
{
	return thread->stop != 0;
}

