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
#include <linux/timer.h>
#include <net/ip.h>
#include <net/udp.h>

#include "u2k_thread.h"
#include "pkt_dump.h"
#include "bbox_file.h"
#include "can_ccap.h"

#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8

enum CMD_TO_WRITER {
	CMD_START,
	CMD_STOP,
	CMD_END
};

static struct ccap_writer {
	struct u2k_thread *task;
	struct wait_queue_head wq_head;
	uint32_t overflow_cnt;
	uint32_t write_fail_cnt;
	uint32_t limited_size;
	uint32_t fifo_size;
	STRUCT_KFIFO_PTR(struct sk_buff *) fifo;
	spinlock_t fifo_lock;
	const struct pkt_dump_ops *dump_ops;
	void *file_handle;
} g_ccap_writer;

#define CAP_BY_PT 0x1
#define CAP_BY_NF 0x2
static struct can_ccap_s {
	enum {
		CCAP_UNINIT,
		CCAP_STOP,
		CCAP_ACTIVE,
		CCAP_PAUSE
	} state;
	struct ccap_writer *writer;
	void (*free)(void*);
	struct nf_hook_ops can_hook;
	struct packet_type pt;
	uint16_t ether_type;
	uint16_t udp_port;
	uint32_t cap_flag; /*see CAP_BY_PT, CAP_BY_NF */ 
	uint32_t newfile_timer_delta;
	struct timer_list newfile_timer;
} g_ccap;


static int ccap_writer_dump_skb(struct ccap_writer *writer, struct sk_buff *skb)
{
	int ret;
	
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
	}
	return 0;
}

static void new_dump_file(struct ccap_writer *writer)
{
	struct tm tm;
	char filename[84];
	struct pkt_dump_more_param more = {
		.tstamp_precision = PCAP_TSTAMP_PRECISION_NANO,
		.link = LINKTYPE_CAN_SOCKETCAN,
	};
		
	time64_to_tm(ktime_get_real_seconds(), 0, &tm);
	snprintf(filename, sizeof(filename), "%02d%02d%02d%02d%02d%02d.",
		(int)tm.tm_year + 1900 -2000,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec
		);
	writer->file_handle = writer->dump_ops->open(filename, 0644, &more);
	if (!writer->file_handle)
		pr_err("bbox::can_ccap: open dump file %s fail", filename);
}

static void close_dump_file(struct ccap_writer *writer)
{
	if (writer->file_handle)
		writer->dump_ops->close(writer->file_handle);
	writer->file_handle = NULL;
}

static int send_writer_cmd(struct ccap_writer *writer, uint32_t cmd)
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

static void execute_writer_cmd(struct ccap_writer *writer, uint32_t cmd)
{
	switch (cmd) {
	case CMD_START:
		close_dump_file(writer);
		new_dump_file(writer);
		break;
	case CMD_STOP:
		close_dump_file(writer);
		break;
	default:
		break;
	}
}

static int ccap_writer_kthread(void *data, struct u2k_thread *thread)
{
	struct ccap_writer *writer = data;
	struct can_ccap_s *ccap = &g_ccap;
	struct sk_buff *skb;
	int ret;

	bbox_file_create_ioctx(NULL);
	
	while (!u2k_thread_should_stop(thread)) {
		wait_event(writer->wq_head, kfifo_len(&writer->fifo) \
			|| u2k_thread_should_stop(thread));
		
		while (kfifo_get(&writer->fifo, &skb)) {
			if ((unsigned long)skb >= CMD_END) {
				ret = writer->dump_ops->dump_buf(writer->file_handle, skb->data, skb->len);
				kfree_skb(skb);
				if (unlikely(ret))
					writer->write_fail_cnt++;

				/* generate new file if size more than limited*/
				if (writer->dump_ops->dump_pos(writer->file_handle) >= writer->limited_size) {
					close_dump_file(writer);
					new_dump_file(writer);
				
					/* reset timer */
					if (ccap->newfile_timer_delta)
						mod_timer(&ccap->newfile_timer, jiffies + ccap->newfile_timer_delta);
				}
			} else
				execute_writer_cmd(writer, (uint32_t)(long)skb);
		}
	}

	bbox_file_destory_ioctx(NULL);
	return 0;
}

static void newfile_timer(struct timer_list *t)
{
	struct can_ccap_s *ccap = from_timer(ccap, t, newfile_timer);

	if (ccap->state == CCAP_ACTIVE) {
		mod_timer(t, jiffies + ccap->newfile_timer_delta);
		send_writer_cmd(ccap->writer, CMD_START);
	}
}

static int init_ccap_writer(struct ccap_writer *writer, uint32_t fifo_size, const char *format)
{
	int ret;

	writer->overflow_cnt = 0;
	writer->write_fail_cnt = 0;
	writer->dump_ops = pkt_dump_get(format);
	if (!writer->dump_ops) {
		pr_err("bbox::can_ccap: cannot find dump for %s", format);
		return -ENOTSUPP;
	}
	
	writer->limited_size = 0x7f000000;
	
	ret = kfifo_alloc(&writer->fifo, fifo_size, GFP_KERNEL);
	if (ret)
		return ret;

	init_waitqueue_head(&writer->wq_head);
	spin_lock_init(&writer->fifo_lock);
	
	writer->task = u2k_thread_run((unsigned long)ccap_writer_kthread, (unsigned long)writer);
	if (IS_ERR_OR_NULL(writer->task)) {
		kfifo_free(&writer->fifo);
		return PTR_ERR(writer->task);
	}
	return 0;
}

static void uinit_ccap_writer(struct ccap_writer *writer)
{
	(void)u2k_thread_stop(writer->task);
	kfifo_free(&writer->fifo);

	pkt_dump_put(writer->dump_ops);
	writer->dump_ops = NULL;
	
	if (writer->overflow_cnt)
		printk("can: write overflow: %u", writer->overflow_cnt);
	if (writer->write_fail_cnt)
		printk("can: write fail: %u", writer->write_fail_cnt);
}

static int packet_cap (struct sk_buff *skb,
					 struct net_device *ndev,
					 struct packet_type *pt,
					 struct net_device *ndev_orig)
{
	struct can_ccap_s *ccap = container_of(pt, struct can_ccap_s, pt);

	if (ccap->state == CCAP_ACTIVE) 
		(void)ccap_writer_dump_skb(ccap->writer, skb);
	kfree_skb(skb);
	return 0;
}

static unsigned int can_nf_hook_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct can_ccap_s *ccan = priv;

	if (ccan->state == CCAP_ACTIVE) {
		struct iphdr _iphdr;
		struct udphdr _udphdr;
		struct iphdr *iph;
    	struct udphdr *udph;

		iph = skb_header_pointer(skb, 0, sizeof(_iphdr), &_iphdr);
		if (iph && iph->protocol == IPPROTO_UDP) {
			udph = skb_header_pointer(skb, IP_HDR_LEN, sizeof(_udphdr), &_udphdr);
			if (udph && udph->dest == ccan->udp_port) {
				skb->data += 28;
				skb->len -= 28;
				ccap_writer_dump_skb(ccan->writer, skb);
				return NF_STOLEN;
			}
		}
	}
	return NF_ACCEPT;
}

static void init_net_hook(struct nf_hook_ops *hook)
{
	hook->hook = can_nf_hook_in,
	hook->priv = NULL,
	hook->pf = NFPROTO_INET,
	hook->hooknum = NF_INET_PRE_ROUTING,
	hook->priority = 1,
	hook->dev = NULL;
}

struct can_ccap_s *query_can_ccap(void)
{
	return g_ccap.state != CCAP_UNINIT ? &g_ccap : NULL;
}

int ccap_open(const char *format)
{
	struct can_ccap_s *ccap = query_can_ccap();
	int ret;
	
	if (ccap)
		return -EALREADY;
	
	ccap = &g_ccap;

	ret = init_ccap_writer(&g_ccap_writer, 2048, format);
	if (ret)
		return ret;
	ccap->writer = &g_ccap_writer;

	ccap->pt.type = 0,
	ccap->pt.func = packet_cap,
	
	init_net_hook(&ccap->can_hook);
	ccap->can_hook.priv = ccap;

	timer_setup(&ccap->newfile_timer, newfile_timer, 0);
	
	ccap->state = CCAP_STOP;
		
	return 0;
}


void close_can_ccap(void)
{
	(void)ccap_close(query_can_ccap());
}

int set_coe_args(uint16_t ether_type, uint16_t udp_port)
{
	if (g_ccap.state != CCAP_UNINIT
		&& g_ccap.state != CCAP_STOP)
		return -EBUSY;
	
	g_ccap.ether_type = ether_type;
	g_ccap.udp_port = udp_port;
	return 0;
}

int ccap_close(struct can_ccap_s *ccap)
{
	if (!ccap)
		return -EINVAL;
	
	(void)ccap_stop(ccap, NULL);
	
	uinit_ccap_writer(ccap->writer);
	ccap->state = CCAP_UNINIT;
	if (ccap->free)
		ccap->free(ccap);
	return 0;
}

int ccap_start(struct can_ccap_s *ccap, const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{
	int ret = 0;
	
	if (!ccap)
		return -EINVAL;

	if (ccap->state != CCAP_STOP)
		return -EBUSY;

	if (!(ccap->ether_type | ccap->udp_port))
		return -ENOENT;

	ccap->newfile_timer_delta = newfile_period * 60 * HZ;
	ccap->writer->limited_size = max_filesize ? max_filesize : 0x7F000000;
	
	ccap->state = CCAP_ACTIVE;
	send_writer_cmd(ccap->writer, CMD_START);
	
	if (ccap->ether_type) {
		ccap->pt.type = ccap->ether_type;
		ccap->pt.dev = dev_get_by_name(&init_net, "ipc0");
		net_enable_timestamp();
		dev_add_pack(&ccap->pt);
		ccap->cap_flag |= CAP_BY_PT;
	}

	if (ccap->udp_port) {
		ccap->can_hook.dev = dev_get_by_name(&init_net, "ipc0");
		ret = nf_register_net_hook(&init_net, &ccap->can_hook);
		ccap->cap_flag |= CAP_BY_NF;
	}

	if (ccap->newfile_timer_delta)
		mod_timer(&ccap->newfile_timer, jiffies + ccap->newfile_timer_delta);
	return ret;
}

int ccap_stop(struct can_ccap_s *ccap, const char *name_list)
{
	int state;
	
	if (!ccap)
		return -EINVAL;

	state = ccap->state;
	ccap->state = CCAP_STOP;

	if (state == CCAP_ACTIVE
		|| state == CCAP_PAUSE) {

		if (ccap->newfile_timer_delta)
			del_timer_sync(&ccap->newfile_timer);
		
		/* stop pt */
		if (ccap->cap_flag & CAP_BY_PT) {
			dev_remove_pack(&ccap->pt);
			net_disable_timestamp();
			if (ccap->pt.dev) {
				dev_put(ccap->pt.dev);
			}
		}
		
		/* stop nf hook */
		if (ccap->cap_flag & CAP_BY_NF) {
			nf_unregister_net_hook(&init_net, &ccap->can_hook);
			if (ccap->can_hook.dev) {
				dev_put(ccap->can_hook.dev);
				ccap->can_hook.dev = 0;
			}
		}
		ccap->cap_flag = 0;
		send_writer_cmd(ccap->writer, CMD_STOP);
	}

	return 0;
}

int ccap_new_dump(struct can_ccap_s *ccap, const char *filename)
{	
	if (!ccap)
		return -EINVAL;
	
	if (ccap->state != CCAP_ACTIVE
		&& ccap->state != CCAP_PAUSE)
		return -EBUSY;
	
	return send_writer_cmd(ccap->writer, CMD_START);
}

int ccap_pause(struct can_ccap_s *ccap)
{
	if (!ccap)
		return -EINVAL;
	
	if (ccap->state != CCAP_ACTIVE)
		return -EBUSY;
	ccap->state = CCAP_PAUSE;
	return 0;
}

int ccap_continue(struct can_ccap_s *ccap)
{
	if (!ccap)
		return -EINVAL;
	
	if (ccap->state != CCAP_PAUSE)
		return -EBUSY;
	ccap->state = CCAP_ACTIVE;
	return 0;
}

