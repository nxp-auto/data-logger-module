/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stdbool.h>
#endif
#ifdef ___cplusplus
extern "C" {
#endif

#pragma pack(1)

/* encapsulation information for CAN over ethernet */
struct encapsulation_ctrl {
	enum {
		L2_ENCAPS, 
		UDP_ENCAPS
	} __attribute__ ((__packed__)) packet_type;
	union {
		struct {
			uint16_t ether_type;
			uint8_t hwaddr[6];
		} l2_addr;
		
		struct {
			uint32_t ip;
			uint16_t port;
		} l4_addr;
	};
};
#pragma pack()

enum pcap_type {
	ETH_PCAP = 0,
	CAN_PCAP = 1,
};

int bbox_open_capture(int cap_type, const char *format);
int bbox_close_capture(int cap_type);

/*
 * Dump ethernet frame to black box
 * @dev_list: name of Ethernet devices sperated by comma, for example: "eth0,pfe0,pfe2"
               NUll stands for all ethernet devices
 */
int bbox_start_dump_ethernet(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize);
int bbox_stop_dump_ethernet(const char *dev_list);
/*
 * close the old file and generate new dump file
 */
int bbox_new_ethernet_dump(const char *filename);

int bbox_set_coe_args(uint16_t ether_type, uint16_t udp_port);
/*
 * Extract CAN frame from Ethernet frame and dump it
 * @dev_list: name of Ethernet devices sperated by comma, for example: "ipc0,pfe1"
               NUll stands for all ethernet devices
 */
int bbox_start_dump_coe(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize);
int bbox_stop_dump_coe(const char *dev_list);
/*
 * close the old file and generate new dump file
 */
int bbox_new_coe_dump(const char *filename);


int bbox_start_transfer(struct encapsulation_ctrl *encaps);
int bbox_stop_transfer(void);

int bbox_set_channel(uint16_t channel, const char *info);
int bbox_update_channel_baudrate(uint16_t channel, uint32_t baudrate);
/*
 * @max_num: maximum number of files open at the same time
 * @path: path to save bbox file
 * @secure_path: secure path to save bbox file
 * @log_filename: name of file to record file operations
 * @return 0 : success; other : fail
 */
int bbox_file_init(unsigned int max_num, const char *path, const char *secure_path, const char *log_filename);
void bbox_file_uninit(void);

struct diag_msg {
	uint32_t id;
	uint16_t id_bits;
	uint16_t data_len;
	uint8_t data[0];
};

int bbox_diagnosis_send(uint16_t channel, struct diag_msg *dmesg);

#ifdef ___cplusplus
}
#endif
