/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/if_vlan.h>
#include <asm/uaccess.h>

#include "bbox_file.h"
#include "coe.h"
#include "pcap_dump.h"

#define SNAP_LEN 0x10000

struct pcap_dump_s {
	int tstamp_precision;
	linktype_t link;
	struct bbox_file *file;
};

static void *g_stm7_iobase;

static int write(struct pcap_dump_s *pdump, void *buff, size_t count)
{
	int ret = -EINVAL;

	if (pdump->file) {
		ret = bbox_file_write(pdump->file, buff, count);
		if (ret != count)
			pr_warn("bbox_file_write.write = %d\n", ret);
	}
	return ret;
}

static int write_header(struct pcap_dump_s *pdump)
{
	struct pcap_file_header hdr;

	hdr.magic = pdump->tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = sys_tz.tz_minuteswest / 60;
	hdr.snaplen = SNAP_LEN;
	hdr.sigfigs = 0;
	hdr.linktype = pdump->link;

	if (write(pdump, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		printk("write pcap header fail\n");
		return -EIO;
	}
	return 0;
}

/* fix filename, append can.pcap or pcap if last char is '.' according to link type  */
static const char *fix_filename(const char *name, linktype_t link, char *buff)
{
	int len = strlen(name);

	if (name[len - 1] == '.') {
		sprintf(buff, "%s%s", name,link ==  LINKTYPE_ETHERNET ? "pcap" : "can.pcap");
		return buff;
	}
	return name;
}

void *pcap_open_dump_file(const char *name, umode_t mode, struct pkt_dump_more_param *param)
{
	struct pcap_dump_s *pdump;
	char filename_buf[128];
	
	if ((param->tstamp_precision != PCAP_TSTAMP_PRECISION_MICRO
		&& param->tstamp_precision != PCAP_TSTAMP_PRECISION_NANO)
		|| !name)
		return NULL;
	
	if (param->link != LINKTYPE_ETHERNET
		&& param->link != LINKTYPE_CAN_SOCKETCAN)
		return NULL;
	
	pdump = kzalloc(sizeof(*pdump), GFP_KERNEL);
	if (!pdump)
		return NULL;

	pdump->tstamp_precision = param->tstamp_precision;
	pdump->link = param->link;
	name = fix_filename(name, param->link, filename_buf);
	pdump->file = bbox_file_open(name, 0);
	if (IS_ERR_OR_NULL(pdump->file)) {
		kfree(pdump);
		pr_err("open file:%s fail\n", name);
		return NULL;
	}
	if (write_header(pdump)) {
		pcap_close_dump(pdump);
		return NULL;
	}

	/* map stm7 register for delta value of timestamp */
	if (param->link == LINKTYPE_CAN_SOCKETCAN && !g_stm7_iobase)
		g_stm7_iobase = ioremap(0x40228000, 0x100);
	return pdump;
}

int pcap_close_dump(void *handle)
{
	int ret;
	struct pcap_dump_s *pdump = handle;
	
	if (!pdump)
		return -EINVAL;
	ret = bbox_file_close(pdump->file);
	if (ret) {
		pr_err("bbox_file_close() fail:%d", ret);
		return ret;
	}
	kfree(pdump);
	return 0;
}

int pcap_dump_skb(void *handle, struct sk_buff *skb)
{
	struct pcap_sf_pkthdr pkthdr;
	int ret;
	int offset = 0;
	struct timespec ts;
	struct pcap_dump_s *pdump = handle;
	
	if (!pdump || !skb)
		return -EINVAL;

	if (skb->pkt_type != PACKET_OUTGOING) {
		offset -= 14;
		if (skb_vlan_tag_present(skb))
			offset -= 4;
	}

	skb_get_timestampns(skb, &ts);
	pkthdr.t1 = ts.tv_sec;
	if (pdump->tstamp_precision == PCAP_TSTAMP_PRECISION_NANO)
		pkthdr.t2 = ts.tv_nsec;
	else
		pkthdr.t2 = ts.tv_nsec / 1000;
	
	pkthdr.caplen = pkthdr.len = skb->len - offset;
	ret = write(pdump, &pkthdr, sizeof(pkthdr));
	if (ret != sizeof(pkthdr)) {
		printk("write pkthdr fail");
		return -EIO;
	}
	ret = write(pdump, skb->data + offset, pkthdr.caplen);
	if (ret !=  pkthdr.caplen)
		printk("write pkt data fail");
	return 0;
}

static uint32_t read_curr_number(void)
{
	if (g_stm7_iobase)
		return ioread32(g_stm7_iobase + 4);/* read stm7 CNT register */
	return 0;
}

static void get_timestamp(struct coe_timestamp *ts, struct timespec64 *real_ts)
{	
#define NS_PER_S 1000000000
	if (ts->leading & 0x8000) {
		const uint32_t now = read_curr_number();
		
		ktime_get_real_ts64(real_ts);
		if (ts->cnt.freq) {
			const uint32_t delta_ns = (uint64_t)(now - ts->cnt.number) * NS_PER_S / ts->cnt.freq;

			real_ts->tv_nsec -= delta_ns;
			while (real_ts->tv_nsec < 0) {
				real_ts->tv_nsec += NS_PER_S;
				real_ts->tv_sec--;
			}
		}
	} else {
		real_ts->tv_sec = ((uint64_t)ts->leading << 32) | ts->t.sec;
		real_ts->tv_nsec = ts->t.nsec;
	}
}

int pcap_dump_buffer(void *handle, void *buf, uint32_t len)
{
	struct pcap_sf_pkthdr pkthdr;
	struct pcap_can_pkthdr can_pkthdr;
	struct timespec64 real_ts;
	struct coe_msg *coe = buf;
	int ret;
	struct pcap_dump_s *pdump = handle;
	
	if (!pdump || !buf || len == 0)
		return -EINVAL;

	if (len != (COE_MSG_HDR_LEN + coe->data_len))
		return -EINVAL;

	get_timestamp(&coe->ts, &real_ts);
	if (pdump->tstamp_precision == PCAP_TSTAMP_PRECISION_NANO) {
		pkthdr.t1 = real_ts.tv_sec;
		pkthdr.t2 = real_ts.tv_nsec;
	} else {
		pkthdr.t1 = real_ts.tv_sec;
		pkthdr.t2 = real_ts.tv_nsec * 1000;
	}
	pkthdr.caplen = pkthdr.len = sizeof(can_pkthdr) + coe->data_len;

	can_pkthdr.id = coe->msg_id;
	if (coe->flags)
		can_pkthdr.id |= 1<<29;
	if (coe->msg_id & 0x1ffff800)
		can_pkthdr.id |= 1u << 31;
	can_pkthdr.id = htonl(can_pkthdr.id);
	can_pkthdr.len = coe->data_len;
	can_pkthdr.padding = 0;
	can_pkthdr.channel_id = htons(coe->channel_id);
	
	ret = write(pdump, &pkthdr, sizeof(pkthdr));
	if (ret != sizeof(pkthdr)) {
		printk("write pkthdr fail");
		return -EIO;
	}
	
	write(pdump, &can_pkthdr, sizeof(can_pkthdr));
	write(pdump, coe->data, coe->data_len);
	return 0;
}


uint64_t pcap_dump_pos(void *handle)
{
	struct pcap_dump_s *pdump = handle;
	
	return bbox_file_pos(pdump->file);
}

static const struct pkt_dump_ops g_eth_pcap_dump_ops = {
	.name = "pcap",
	.owner = THIS_MODULE,
	.open = pcap_open_dump_file,
	.close = pcap_close_dump,
	.dump_buf = pcap_dump_buffer,
	.dump_skb = pcap_dump_skb,
	.dump_pos = pcap_dump_pos,
};

int init_pcap_dump(void)
{
	return pkt_dump_reg(&g_eth_pcap_dump_ops);
}

void uninit_pcap_dump(void)
{
	pkt_dump_unreg(&g_eth_pcap_dump_ops);
	if (g_stm7_iobase) {
		iounmap(g_stm7_iobase);
		g_stm7_iobase = NULL;
	}
}

