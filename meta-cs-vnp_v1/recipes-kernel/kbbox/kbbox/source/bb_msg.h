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
#endif
#ifdef ___cplusplus
extern "C" {
#endif

enum bb_msg_type {
	BB_MSG_UNSPEC = 0,
	BB_MSG_REQ = 1,
	BB_MSG_RSP = 2,
	BB_MSG_EVENT = 3,
	BB_MSG_CONFIRM = 4
};

struct bb_msg {
	uint8_t ver;
	uint8_t ver_check;
	uint16_t seq;	
	uint16_t type; /* see enum bb_msg_type */
	uint16_t func_code;	
	union {
		uint16_t reply_len; /* use reply_len when requset, ret_code when reply */
		uint16_t reply_code;
	};
	uint16_t payload_len;	
	uint32_t data[0];
};

#define BB_MSG_HDRLEN	 ((long)&((struct bb_msg*)0)->data)

enum bb_msg_arg_type {
	BB_ARG_VALUE = 0,
	BB_ARG_POINTER_IN = 0x1,
	BB_ARG_POINTER_OUT = 0x2,
};
#define BB_ARG_POINTER_MASK (BB_ARG_POINTER_IN | BB_ARG_POINTER_OUT)

struct bb_msg_arg {
	uint16_t type;
	uint16_t len;
	uint32_t val;
};

struct bb_req_msg {
	uint8_t argc;
	uint8_t reserved[3];
	struct bb_msg_arg args[0];
};

struct bb_rsp_msg {
	int func_ret;
	uint8_t argc;
	uint8_t reserved[3];
	struct bb_msg_arg args[0];
};

#define BB_MSG_LEN(x) (BB_MSG_HDRLEN + (x)->payload_len)
#define BB_REPLY_MSG_LEN(x) (BB_MSG_HDRLEN + (x)->reply_len)
#define BB_SET_MSG_LEN(x, len) do {(x)->payload_len = (len) - BB_MSG_HDRLEN;} while (0)

#define REQ_MSG_PAYLOAD(req) (void*)(&(req)->args[(req)->argc])
#define REQ_MSG_ARG_PTR(req, x) ((req)->args[x].len ? REQ_MSG_PAYLOAD(req) + (req)->args[x].val : NULL)

#define RSP_MSG_PAYLOAD(rsp) (void*)(&(rsp)->args[(rsp)->argc])

#define BB_MSG_FUNC_TEST 0

#ifdef ___cplusplus
}
#endif
