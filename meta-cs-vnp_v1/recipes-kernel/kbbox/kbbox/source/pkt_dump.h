/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#ifdef __KERNEL__

#include <linux/skbuff.h>

#define PCAP_TSTAMP_PRECISION_MICRO	0	/* use timestamps with microsecond precision, default */
#define PCAP_TSTAMP_PRECISION_NANO	1	/* use timestamps with nanosecond precision */

typedef enum {
	LINKTYPE_ETHERNET = 1,
	LINKTYPE_CAN_SOCKETCAN = 227
} linktype_t;

struct pkt_dump_more_param {
	int tstamp_precision;
	linktype_t link;
};


struct pkt_dump_ops {
	const char *name;
	struct module *owner;
	void *(*open)(const char *filename, umode_t mode, struct pkt_dump_more_param *param);
	int (*close)(void *handle);
	int (*dump_buf)(void *handle, void *buf, uint32_t len);
	int (*dump_skb)(void *handle, struct sk_buff *skb);
	uint64_t (*dump_pos)(void *handle);
};

int pkt_dump_reg(const struct pkt_dump_ops *ops);
void pkt_dump_unreg(const struct pkt_dump_ops *ops);
const struct pkt_dump_ops *pkt_dump_get(const char *name);
void pkt_dump_put(const struct pkt_dump_ops *ops);
#endif

