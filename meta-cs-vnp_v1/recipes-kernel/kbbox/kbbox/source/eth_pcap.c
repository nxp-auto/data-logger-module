/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netdevice.h>
//#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/kfifo.h>
#include <linux/spinlock.h>

#include "u2k_thread.h"
#include "pcap_dump.h"
#include "bbox_file.h"
#include "eth_pcap.h"

enum CMD_TO_WRITER {
	CMD_START,
	CMD_STOP,
	CMD_END
};

static struct pcap_writer {
	struct u2k_thread *task;
	struct wait_queue_head wq_head;
	uint32_t overflow_cnt;
	uint32_t write_fail_cnt;
	uint32_t limited_size;
	uint32_t fifo_size;
	STRUCT_KFIFO_PTR(struct sk_buff *) fifo;
	spinlock_t fifo_lock;
	void *dump;
} g_pcap_writer;

static struct eth_pcap_s {
	enum {
		PCAP_UNINIT,
		PCAP_STOP,
		PCAP_ACTIVE,
		PCAP_PAUSE
	} state;
	struct pcap_writer *writer;
	void (*free)(void*);
	struct packet_type pt;
	uint32_t newfile_timer_delta;
	struct timer_list newfile_timer;
	struct net_device *exclude_ndev;
} g_pcap;

static int pcap_writer_dump_skb(struct pcap_writer *writer, struct sk_buff *skb)
{
	int ret;
	skb = skb_get(skb);
	
	if (skb) {
		unsigned long flags;

		spin_lock_irqsave(&writer->fifo_lock, flags);
		ret = kfifo_put(&writer->fifo, skb);
		spin_unlock_irqrestore(&writer->fifo_lock, flags);
		
		wake_up(&writer->wq_head);
		if (!ret) {
			kfree_skb(skb);
			writer->overflow_cnt++;
			return -1;
		}
		return 0;
	}
	return -ENOMEM;
}

static int packet_cap (struct sk_buff *skb,
					 struct net_device *ndev,
					 struct packet_type *pt,
					 struct net_device *ndev_orig)
{
	struct eth_pcap_s *pcap = container_of(pt, struct eth_pcap_s, pt);

	if (pcap->state == PCAP_ACTIVE
		&& ndev != pcap->exclude_ndev) 
		(void)pcap_writer_dump_skb(pcap->writer, skb);
	kfree_skb(skb);
	return 0;
}

static void *new_dump_file(void)
{
	struct tm tm;
	char filename[84];
	struct pkt_dump_more_param more = {
		.tstamp_precision = PCAP_TSTAMP_PRECISION_NANO,
		.link = LINKTYPE_ETHERNET,
	};
	
	time64_to_tm(ktime_get_real_seconds(), 0, &tm);
	snprintf(filename, sizeof(filename), "%02d%02d%02d%02d%02d%02d.pcap",
		(int)tm.tm_year + 1900 -2000,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec
		);
	return pcap_open_dump_file(filename, 0644, &more);
}

static int send_writer_cmd(struct pcap_writer *writer, uint32_t cmd)
{
	int retry_cnt = HZ;
	int ret;
	unsigned long flags;
	
RETRY:
	spin_lock_irqsave(&writer->fifo_lock, flags);
	ret = kfifo_put(&writer->fifo, (void*)(unsigned long)cmd);
	spin_unlock_irqrestore(&writer->fifo_lock, flags);
	wake_up(&writer->wq_head);
	if (!irq_count()) {
		if (ret == 0 && retry_cnt--) {
			schedule_timeout_uninterruptible(1);
			goto RETRY;
		}
	}
	return !ret;
}

static void execute_writer_cmd(struct pcap_writer *writer, uint32_t cmd)
{
	switch (cmd) {
	case CMD_START:
		if (writer->dump)
			pcap_close_dump(writer->dump);
		writer->dump = new_dump_file();
		break;
	case CMD_STOP:
		pcap_close_dump(writer->dump);
		writer->dump = NULL;
		break;
	default:
		break;
	}
}

static int pcap_writer_kthread(void *data, struct u2k_thread *thread)
{
	struct pcap_writer *writer = data;
	struct eth_pcap_s *pcap = &g_pcap;
	struct sk_buff *skb;
	int ret;

	bbox_file_create_ioctx(NULL);
	
	while (!u2k_thread_should_stop(thread)) {
		wait_event(writer->wq_head, kfifo_len(&writer->fifo) \
			|| u2k_thread_should_stop(thread));
		
		while (kfifo_get(&writer->fifo, &skb)) {
			if ((unsigned long)skb >= CMD_END) {
				ret = pcap_dump_skb(writer->dump, skb);
				kfree_skb(skb);
				if (unlikely(ret))
					writer->write_fail_cnt++;
				
				/* generate new file if size more than limited*/
				if (pcap_dump_pos(writer->dump) >= writer->limited_size) {
					pcap_close_dump(writer->dump);
					writer->dump = new_dump_file();

					/* reset timer */
					if (pcap->newfile_timer_delta)
						mod_timer(&pcap->newfile_timer, jiffies + pcap->newfile_timer_delta);
				}
			} else 
				execute_writer_cmd(writer, (uint32_t)(unsigned long)skb);
		}
	}

	bbox_file_destory_ioctx(NULL);
	return 0;
}

static void newfile_timer(struct timer_list *t)
{
	struct eth_pcap_s *pcap = from_timer(pcap, t, newfile_timer);

	if (pcap->state == PCAP_ACTIVE) {
		mod_timer(t, jiffies + pcap->newfile_timer_delta);
		send_writer_cmd(pcap->writer, CMD_START);
	}
}

static int init_pcap_writer(struct pcap_writer *writer, uint32_t fifo_size, const char *format)
{
	int ret;
	
	writer->dump = NULL;
	writer->overflow_cnt = 0;
	writer->write_fail_cnt = 0;
	ret = kfifo_alloc(&writer->fifo, fifo_size, GFP_KERNEL);
	if (ret)
		return ret;

	init_waitqueue_head(&writer->wq_head);
	spin_lock_init(&writer->fifo_lock);
	
	//writer->task = kthread_run(pcap_writer_kthread, writer, "pcap_wr%d", 0);
	writer->task = u2k_thread_run((unsigned long)pcap_writer_kthread, (unsigned long)writer);
	if (IS_ERR_OR_NULL(writer->task)) {
		kfifo_free(&writer->fifo);
		return PTR_ERR(writer->task);
	}
	return 0;
}

static void uinit_pcap_writer(struct pcap_writer *writer)
{
	//(void)kthread_stop(writer->task);
	u2k_thread_stop(writer->task);
	kfifo_free(&writer->fifo);
	if (writer->overflow_cnt)
		printk("eth: write overflow: %u", writer->overflow_cnt);
	if (writer->write_fail_cnt)
		printk("eth: write fail: %u", writer->write_fail_cnt);
}

struct eth_pcap_s *query_eth_pcap(void)
{
	return g_pcap.state != PCAP_UNINIT ? &g_pcap : NULL;
}

int pcap_open(const char *format)
{
	struct eth_pcap_s *pcap = query_eth_pcap();
	int ret;
	
	if (pcap)
		return -EALREADY;
	
	pcap = &g_pcap;
	pcap->writer = &g_pcap_writer;
	ret = init_pcap_writer(pcap->writer, 2048, format);
	if (ret)
		return ret;
	
	pcap->pt.type = cpu_to_be16(ETH_P_ALL),
	pcap->pt.func = packet_cap,
	
	timer_setup(&pcap->newfile_timer, newfile_timer, 0);
	
	pcap->state = PCAP_STOP;
	pcap->exclude_ndev = dev_get_by_name(&init_net, "ipc0");
	return 0;
}


void close_eth_pcap(void)
{
	(void)pcap_close(query_eth_pcap());
}

int pcap_close(struct eth_pcap_s *pcap)
{
	if (!pcap)
		return -EINVAL;
	
	(void)pcap_stop(pcap, NULL);
	
	uinit_pcap_writer(pcap->writer);
	if (pcap->exclude_ndev) {
		dev_put(pcap->exclude_ndev);
		pcap->exclude_ndev = NULL;
	}
	pcap->state = PCAP_UNINIT;
	if (pcap->free)
		pcap->free(pcap);
	return 0;
}

int pcap_start(struct eth_pcap_s *pcap, const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{	
	if (!pcap)
		return -EINVAL;

	if (pcap->state != PCAP_STOP)
		return -EBUSY;

	pcap->newfile_timer_delta = newfile_period * 60 * HZ;
	pcap->writer->limited_size = max_filesize ? max_filesize : 0x7F000000;
	
	pcap->state = PCAP_ACTIVE;
	send_writer_cmd(pcap->writer, CMD_START);
	net_enable_timestamp();
	dev_add_pack(&pcap->pt);
	if (pcap->newfile_timer_delta)
		mod_timer(&pcap->newfile_timer, jiffies + pcap->newfile_timer_delta);
	return 0;
}

int pcap_stop(struct eth_pcap_s *pcap, const char *name_list)
{
	int state;
	
	if (!pcap)
		return -EINVAL;

	state = pcap->state;
	pcap->state = PCAP_STOP;
	
	if (state == PCAP_ACTIVE
		|| state == PCAP_PAUSE) {
		
		if (pcap->newfile_timer_delta)
			del_timer_sync(&pcap->newfile_timer);
		
		dev_remove_pack(&pcap->pt);
		net_disable_timestamp();
		send_writer_cmd(pcap->writer, CMD_STOP);
	}

	return 0;
}

int pcap_new_dump(struct eth_pcap_s *pcap, const char *filename)
{
	if (!pcap)
		return -EINVAL;
	
	if (pcap->state != PCAP_ACTIVE
		&& pcap->state != PCAP_PAUSE)
		return -EBUSY;

	return send_writer_cmd(pcap->writer, CMD_START);
}

int pcap_pause(struct eth_pcap_s *pcap)
{
	if (!pcap)
		return -EINVAL;
	
	if (pcap->state != PCAP_ACTIVE)
		return -EBUSY;
	pcap->state = PCAP_PAUSE;
	return 0;
}

int pcap_continue(struct eth_pcap_s *pcap)
{
	if (!pcap)
		return -EINVAL;
	
	if (pcap->state != PCAP_PAUSE)
		return -EBUSY;
	pcap->state = PCAP_ACTIVE;
	return 0;
}




