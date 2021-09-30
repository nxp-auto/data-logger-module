/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/*
 * example about dump pcap file
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>


#include "bbox_api.h"
#include "bbox_disk.h"
#include "bbox_client.h"

unsigned int g_opt_interval = 10;
unsigned int g_opt_filesize = 200000000;

static int start_pcap(void)
{	
	return bbox_start_dump_ethernet(NULL, g_opt_interval, 0);
}

static int stop_pcap(void)
{
	int ret = bbox_stop_dump_ethernet(NULL);

	return ret;
}

static int start_can_cap(void)
{
	const uint16_t udp_port = 5558;
	const uint16_t ether_type = 0;
	
	struct encapsulation_ctrl encaps = {
		.packet_type = UDP_ENCAPS,
		.l4_addr = {
			.ip = htonl(0xC0A80064), /*192.168.0.100*/
			.port = htons(udp_port),
		},
	};
	int ret;
	
	ret = bbox_set_coe_args(htonl(ether_type), htons(udp_port));
	if (ret) {
		fprintf(stderr, "bbox_set_coe_args.ret = %d\n", ret);
		return ret;
	}

	ret = bbox_start_dump_coe(NULL, g_opt_interval, g_opt_filesize);
	if (ret) {
		fprintf(stderr, "bbox_start_dump_coe.ret = %d\n", ret);
		return ret;
	}

	ret= bbox_start_transfer(&encaps);
	if (ret) {
		fprintf(stderr, "bbox_start_transfer.ret = %d\n", ret);
	}
	return 0;
}

static int stop_can_pcap(void)
{
	int ret= bbox_stop_transfer();
	
	if (ret) {
		fprintf(stderr, "bbox_stop_transfer.ret = %d\n", ret);
	}
	ret = bbox_stop_dump_coe(NULL);
	if (ret) {
		fprintf(stderr, "bbox_stop_dump_coe.ret = %d\n", ret);
		return ret;
	}
	return 0;
}

static void do_exit(void)
{
	stop_can_pcap();
	stop_pcap();
	bbox_close_capture(CAN_PCAP);
	bbox_close_capture(ETH_PCAP);
	bbox_file_uninit();
	bbox_close_client();
	exit(0);
}

static void signal_exit(int signum)
{
	printf("signal %d\n", signum);
	do_exit();
}

int main(int argc, char *argv[])
{
	int ret;
	int opt;
	const char *dev = "/dev/nvme0n1";
	struct disk_config diskconfig = {
		.prt_num = 1,
		.partitions = {
			{
				.secure = false,
				.fs_fmt = "ext4",
			},
		},
	};
	
	while ((opt = getopt(argc, argv, "hi:s:")) != -1) {
		switch (opt) {
		case 'i':
			g_opt_interval = strtoul(optarg, NULL, 0);
			break;
		case 's':
			g_opt_filesize = strtoul(optarg, NULL, 0);
			break;
		default:
			printf("%s [-i <interval>] [-s <file size>] storage_device\n", argv[0]);
			printf("\tdefault: %s -i %u %s\n",argv[0], g_opt_interval, dev);
			return 1;
		}
	}

	if (optind < argc) {
		int len;
		
		dev = argv[optind];
		len = strlen(dev);
		if (len > 2
			&& dev[len-2] == 'p'
			&& (dev[len-1] >= '1' && dev[len-1] <= '9')) {
			/* The device is a partition */
			diskconfig.partitions[0].prt_idx = dev[len-1] - '1';
			argv[optind][len-2] = 0;
		}
	}
	
	printf("bbox arguments: interval:%u, storage:%s\n", g_opt_interval, dev);

	ret = bbox_open_client();
	if (ret)
		return ret;
	
	ret = bbox_setup_disk(dev, &diskconfig);
	if (ret) {
		fprintf(stderr, "setup_disk fail. %d\n", ret);
		goto L_close_client;
	}
	
	ret = bbox_open_capture(ETH_PCAP, "pcap");
	if (ret) {
		fprintf(stderr, "Open eth pcap fail. %d\n", ret);
		goto L_uninit_file;
	}
	
	ret = bbox_open_capture(CAN_PCAP, "pcap"); /* pcap for csv */
	if (ret) {
		fprintf(stderr, "Open CAN pcap fail. %d\n", ret);
		//goto L_close_eth_pcap;
	}

	ret = start_pcap();
	if (ret) {
		fprintf(stderr, "Start eth pcap fail. %d\n", ret);
		goto L_close_can_pcap;
	}

	ret = start_can_cap();
	if (ret) {
		fprintf(stderr, "Start can pcap fail. %d\n", ret);
	}
	
	signal(SIGINT, signal_exit);
	
	while (1)
		pause();

	stop_can_pcap();
	stop_pcap();
L_close_can_pcap:
	bbox_close_capture(CAN_PCAP);
	bbox_close_capture(ETH_PCAP);
L_uninit_file:
	bbox_file_uninit();
L_close_client:
	bbox_close_client();
	return ret;
}


