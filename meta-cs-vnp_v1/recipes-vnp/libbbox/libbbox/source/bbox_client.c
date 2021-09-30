/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "bbox_client.h"
#include "lib.h"
#include "bb_msg_client.h"
#include "bb_netlink.h"
#include "bbox_api.h"
#include "bbox_msg.h"

static bb_client_t g_kernel_client;
static bb_client_t g_m7_client;

static int bb_test(bb_client_t client)
{
	char out[100] = "Hello BB message server!";
	
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_POINTER_IN | BB_ARG_POINTER_OUT,
			.len = sizeof(out),
			.ptr = out,
		},
		{
			.type = BB_ARG_VALUE,
			.len = 4,
			.val = sizeof(out),
		},
	};
	
	int ret = bb_msg_req(client, BB_MSG_FUNC_TEST, 2, args, &ret);

	if (ret) {
		fprintf(stderr, "bb_msg_req(TEST).ret = %d\n", ret);
		return ret;
	}
	printf("bb server test message: %s\n", out);
	return ret;
}

int bbox_open_client(void)
{
	int ret;

	(void)bash_command("modprobe bbox");
	
	ret = bb_msg_open_netlink(&g_kernel_client, getpid(), 0, NETLINK_BB);
	if (ret)
		return ret;

	ret = bb_test(g_kernel_client);
	if (ret) {
		fprintf(stderr, "bb test kernel server fail, close\n");
		bb_msg_close(g_kernel_client);
		g_kernel_client = 0;
		return ret;
	}

	{
		struct bb_udp_args args = {
			.src_port = 0,
			.dest_port = 5559,
			.src_ip = 0,
			.dest_ip = 0xC0A800C8, /*192.168.0.200*/
		};
			
		ret = bb_msg_open_udp(&g_m7_client, &args);
		if (ret) {
			fprintf(stderr, "Warning: Cannot connect M7 server, keep going\n");
			return 0;
		}
		
		ret = bb_test(g_m7_client);
		if (ret) {
			fprintf(stderr, "Warning: bb test M7 server fail, close\n");
			bb_msg_close(g_m7_client);
			g_m7_client = 0;
			return 0;
		}
	}
	return 0;
}

void bbox_close_client(void)
{
	if (g_m7_client) {
		bb_msg_close(g_m7_client);
		g_m7_client = 0;
	}

	if (g_kernel_client) {
		bb_msg_close(g_kernel_client);
		g_kernel_client = 0;
	}
}

int bbox_open_capture(int cap_type, const char *format)
{
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(cap_type),
			.val = cap_type,
		},
		{
			.type = BB_ARG_POINTER_IN,
			.len = format ? strlen(format)+1 : 0,
			.ptr = (void*)format,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_OPEN_CAPTURE, 2, args, &ret);
	return ret;
}

int bbox_close_capture(int cap_type)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(cap_type),
			.val = cap_type,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_CLOSE_CAPTURE, 1, args, &ret);
	return ret;
}

int bbox_start_dump_ethernet(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{
	struct bb_arg args[3] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = dev_list ? strlen(dev_list) + 1 : 0,
			.ptr = (void*)dev_list,
		},
		{
			.type = BB_ARG_VALUE,
			.len = 4,
			.val = newfile_period,
		},
		{
			.type = BB_ARG_VALUE,
			.len = 4,
			.val = max_filesize,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_START_ETHERNET, 3, args, &ret);
	return ret;
}

int bbox_stop_dump_ethernet(const char *dev_list)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = dev_list ? strlen(dev_list) + 1 : 0,
			.ptr = (void*)dev_list,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_STOP_ETHERNET, 1, args, &ret);
	return ret;
}

int bbox_new_ethernet_dump(const char *filename)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = filename ? strlen(filename) + 1 : 0,
			.ptr = (void*)filename,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_NEW_ETHERNET, 1, args, &ret);
	return ret;
}

int bbox_start_dump_coe(const char *dev_list, unsigned int newfile_period, unsigned int max_filesize)
{
	struct bb_arg args[3] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = dev_list ? strlen(dev_list) + 1 : 0,
			.ptr = (void*)dev_list,
		},
		{
			.type = BB_ARG_VALUE,
			.len = 4,
			.val = newfile_period,
		},
		{
			.type = BB_ARG_VALUE,
			.len = 4,
			.val = max_filesize,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_START_COE, 3, args, &ret);
	return ret;
}


int bbox_stop_dump_coe(const char *dev_list)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = dev_list ? strlen(dev_list) + 1 : 0,
			.ptr = (void*)dev_list,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_STOP_COE, 1, args, &ret);
	return ret;
}

int bbox_set_coe_args(uint16_t ether_type, uint16_t udp_port)
{
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(ether_type),
			.val = ether_type,
		},
		
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(udp_port),
			.val = udp_port,
		},
	};
	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_SET_COE_ARGS, 2, args, &ret);
	return ret;
}

int bbox_new_coe_dump(const char *filename)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = filename ? strlen(filename) + 1 : 0,
			.ptr = (void*)filename,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_NEW_COE, 1, args, &ret);
	return ret;
}

int bbox_start_transfer(struct encapsulation_ctrl *encaps)
{
	struct bb_arg args[1] = {
		{
			.type = BB_ARG_POINTER_IN,
			.len = sizeof(*encaps),
			.ptr = encaps,
		},
	};

	int ret = -1;
	
	(void)bb_msg_req(g_m7_client, BBOX_MSG_FUNC_START_TRANSFER, 1, args, &ret);
	return ret;
}

int bbox_stop_transfer(void)
{
	int ret = -1;
	
	(void)bb_msg_req(g_m7_client, BBOX_MSG_FUNC_STOP_TRANSFER, 0, NULL, &ret);
	return ret;
}


int bbox_set_channel(uint16_t channel, const char *info)
{
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(channel),
			.val = channel,
		},
		
		{
			.type = BB_ARG_POINTER_IN,
			.len = info ? strlen(info)+1 : 0,
			.ptr = (void*)info,
		},
	};
	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_SET_CHANNEL, 2, args, &ret);
	return ret;
}

int bbox_update_channel_baudrate(uint16_t channel, uint32_t baudrate)
{
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(channel),
			.val = channel,
		},
		
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(baudrate),
			.val = baudrate,
		},
	};
	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_UPDATE_CHANNEL_BAUDRATE, 2, args, &ret);
	return ret;
}

int bbox_file_init(unsigned int max_num, const char *path, const char *secure_path, const char *log_filename)
{
	struct bb_arg args[4] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(max_num),
			.val = max_num,
		},
		
		{
			.type = BB_ARG_POINTER_IN,
			.len = path ? strlen(path)+1 : 0,
			.ptr = (void*)path,
		},
		{
			.type = BB_ARG_POINTER_IN,
			.len = secure_path ? strlen(secure_path)+1 : 0,
			.ptr = (void*)secure_path,
		},
		{
			.type = BB_ARG_POINTER_IN,
			.len = log_filename ? strlen(log_filename)+1 : 0,
			.ptr = (void*)log_filename,
		},
	};
	int ret = -1;
	
	(void)bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_INIT_FILE, 4, args, &ret);
	return ret;
}

void bbox_file_uninit(void)
{
	int ret = -1;
	
	if (bb_msg_req(g_kernel_client, BBOX_MSG_FUNC_UNINIT_FILE, 0, NULL, &ret))
		printf("bb_msg_req(BBOX_MSG_FUNC_UNINIT_FILE) fail\n");
}


int bbox_diagnosis_send(uint16_t channel, struct diag_msg *dmesg)
{
	struct bb_arg args[2] = {
		{
			.type = BB_ARG_VALUE,
			.len = sizeof(channel),
			.val = channel,
		},
		
		{
			.type = BB_ARG_POINTER_IN,
			.len = sizeof(*dmesg) + dmesg->data_len,
			.ptr = dmesg,
		},
	};
	int ret = -1;
	
	(void)bb_msg_req(g_m7_client, BBOX_MSG_FUNC_SEND_DIAGNOSIS, 2, args, &ret);
	return ret;
}

