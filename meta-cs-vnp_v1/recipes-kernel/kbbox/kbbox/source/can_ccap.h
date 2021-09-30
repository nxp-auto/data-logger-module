/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include <linux/types.h>

struct can_ccap_s *query_can_ccap(void);

void close_can_ccap(void);
int set_coe_args(uint16_t ether_type, uint16_t udp_port);

int ccap_open(const char *format);
int ccap_close(struct can_ccap_s *pcap);
int ccap_start(struct can_ccap_s *pcap, const char *dev_list, unsigned int newfile_period, unsigned int max_filesize);
int ccap_stop(struct can_ccap_s *pcap, const char *name_list);
int ccap_new_dump(struct can_ccap_s *pcap, const char *filename);
int ccap_pause(struct can_ccap_s *pcap);
int ccap_continue(struct can_ccap_s *pcap);


