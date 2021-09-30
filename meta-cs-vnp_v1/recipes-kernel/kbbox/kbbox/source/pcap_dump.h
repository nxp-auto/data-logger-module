/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include <linux/skbuff.h>
#include "pkt_dump.h"

typedef	int bpf_int32;
typedef	unsigned int bpf_u_int32;
typedef unsigned short u_short;

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#define TCPDUMP_MAGIC		0xa1b2c3d4
#define NSEC_TCPDUMP_MAGIC	0xa1b23c4d

struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_sf_pkthdr {
	bpf_u_int32 t1; /* second */
	bpf_u_int32 t2; /* micro-second or nano-second according to precision */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

struct pcap_can_pkthdr {
	/*
	The field containing the CAN ID and flags is in network byte order (big-endian). The bottom 29 bits contain the CAN ID of the frame. The remaining bits are:
	0x20000000 - set if the frame is an error message rather than a data frame.
	0x40000000 - set if the frame is a remote transmission request frame.
	0x80000000 - set if the frame is an extended 29-bit frame rather than a standard 11-bit frame. frame.
	*/
	uint32_t id;
	uint8_t len;
	uint8_t padding;
	uint16_t channel_id;
};

void *pcap_open_dump_file(
			const char *name, 
			umode_t mode,
			struct pkt_dump_more_param *param);
int pcap_close_dump(void *pdump);
int pcap_dump_skb(void *pdump, struct sk_buff *skb);
int pcap_dump_buffer(void *pdump, void *buf, uint32_t len);
uint64_t pcap_dump_pos(void *pdump);

int init_pcap_dump(void);
void uninit_pcap_dump(void);


