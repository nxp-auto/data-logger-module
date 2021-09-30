/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>

#include "eth_pcap.h"
#include "can_ccap.h"
#include "bbox_api.h"

int bbox_open_capture(int cap_type, const char *format)
{
	switch (cap_type) {
	case ETH_PCAP:
		return pcap_open(format);
	case CAN_PCAP:
		return ccap_open(format);
	}
	return -ENOTSUPP;
}

int bbox_close_capture(int cap_type)
{
	switch (cap_type) {
	case ETH_PCAP:
		return pcap_close(query_eth_pcap());
	case CAN_PCAP:
		return ccap_close(query_can_ccap());
	}
	return -ENOTSUPP;
}

int bbox_start_dump_ethernet(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{
	return pcap_start(query_eth_pcap(), dev_list, newfile_period, max_filesize);
}

int bbox_stop_dump_ethernet(const char *dev_list)
{
	return pcap_stop(query_eth_pcap(), dev_list);
}

int bbox_new_ethernet_dump(const char *filename)
{
	return pcap_new_dump(query_eth_pcap(), filename);
}

int bbox_start_dump_coe(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{
	return ccap_start(query_can_ccap(), dev_list, newfile_period, max_filesize);
}

int bbox_stop_dump_coe(const char *dev_list)
{
	return ccap_stop(query_can_ccap(), dev_list);
}

int bbox_new_coe_dump(const char *filename)
{
	return ccap_new_dump(query_can_ccap(), filename);
}

int bbox_set_coe_args(uint16_t ether_type, uint16_t udp_port)
{
	return set_coe_args(ether_type, udp_port);
}

