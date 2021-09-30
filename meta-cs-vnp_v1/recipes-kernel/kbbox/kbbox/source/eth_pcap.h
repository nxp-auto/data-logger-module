/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include <linux/types.h>

struct eth_pcap_s *query_eth_pcap(void);
void close_eth_pcap(void);

int pcap_open(const char *format);
int pcap_close(struct eth_pcap_s *pcap);
int pcap_start(struct eth_pcap_s *pcap, const char *dev_list, unsigned int newfile_period, unsigned int max_filesize);
int pcap_stop(struct eth_pcap_s *pcap, const char *name_list);
int pcap_new_dump(struct eth_pcap_s *pcap, const char *filename);
int pcap_pause(struct eth_pcap_s *pcap);
int pcap_continue(struct eth_pcap_s *pcap);


