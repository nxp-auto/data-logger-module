/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#pragma once
#include "bb_msg.h"

#ifdef ___cplusplus
extern "C" {
#endif

typedef void *bb_client_t;
struct bb_arg {
	uint16_t type;
	uint16_t len;
	union {
		void *ptr;
		int val;
	};
};

struct bb_msg_ops {
	struct bb_msg *(*get_msg_buff)(bb_client_t client, uint32_t payload_len);
	void (*put_msg_buff)(bb_client_t client, struct bb_msg *msg);
	int (*do_req)(bb_client_t client, struct bb_msg *ms);
	int (*send)(bb_client_t client, struct bb_msg *ms);
	int (*recv)(bb_client_t client, struct bb_msg *ms);
	void (*close)(bb_client_t client);
};

struct bb_udp_args {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t src_ip;
	uint32_t dest_ip;
};

int bb_msg_open_netlink(bb_client_t *pclient, int src_pid, int dest_pid, int protocol);
int bb_msg_open_udp(bb_client_t *pclient, struct bb_udp_args *args);

int bb_msg_close(bb_client_t client);

int bb_msg_req(bb_client_t client, uint16_t func_code, uint16_t argc, struct bb_arg args[], int *ret);

#ifdef ___cplusplus
}
#endif

