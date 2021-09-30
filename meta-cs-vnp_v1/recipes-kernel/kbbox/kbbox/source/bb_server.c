/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/kernel.h>
#else
#include <stdio.h>
#include <string.h>
#endif
#include "bb_server.h"

#define BB_TEST_MESSAGE "This is a bb server test message"

static int bb_test(char *msg, int len)
{
	strcat(msg, BB_TEST_MESSAGE);
	return strlen(msg);
}

static uint16_t bb_test_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 2
		|| req->args[0].type != (BB_ARG_POINTER_IN |BB_ARG_POINTER_OUT)
		|| req->args[1].type != BB_ARG_VALUE) {
		return 2;
	}
	rsp->func_ret = bb_test(RSP_MSG_PAYLOAD(rsp) + rsp->args[0].val, req->args[1].len);
	return 0;
}


static req_handler_t g_default_req_handles[] = {
	[BB_MSG_FUNC_TEST] = bb_test_req,
};

static req_handler_t get_req_handler(const struct bb_msg *msg)
{
	req_handler_t handler = bb_req_handler(msg);

	if (handler)
		return handler;
	
	if (msg->func_code < ARRAY_SIZE(g_default_req_handles))
		handler = g_default_req_handles[msg->func_code];
	
	return handler;
}

static void fill_reply_args(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	int i, j;
	uint32_t offset = 0;
	
	/* get reply args count */
	rsp->argc = 0;
	for (i = 0; i < req->argc; i++)
		if (req->args[i].type & BB_ARG_POINTER_OUT)
			rsp->argc++;
	if (!rsp->argc)
		return;

	/* copy reply IN & OUT buffer to OUT buffer */
	for (i = 0, j = 0; i < req->argc; i++) {
		if (req->args[i].type & BB_ARG_POINTER_OUT) {
			rsp->args[j].type = req->args[i].type;
			rsp->args[j].len = req->args[i].len;
			rsp->args[j].val = offset;

			/* copy data to reply buff if it is input and output pointer */
			if (req->args[i].type & BB_ARG_POINTER_IN
				&& req->args[i].len)
				memcpy(RSP_MSG_PAYLOAD(rsp) + offset, REQ_MSG_PAYLOAD(req) + req->args[i].val, req->args[i].len);
			offset += req->args[i].len;
			j++;
		}
	}
}

uint32_t bb_get_msg_reply_len(const struct bb_msg *msg)
{
	uint32_t len = BB_MSG_HDRLEN;
	
	if (msg->type == BB_MSG_REQ) {
		const struct bb_req_msg *req = (struct bb_req_msg *)msg->data;
		int i, j;

		for (i = 0, j = 0; i < req->argc; i++) {
			if (req->args[i].type & BB_ARG_POINTER_OUT) {
				len += req->args[i].len;
				j++;
			}
		}
		len += (long)&((struct bb_rsp_msg*)0)->args[j];
	}
	return len;
}

struct bb_msg *bb_handle_msg(const struct bb_msg *msg, struct bb_msg *reply)
{
	/* init reply message */
	reply->ver = msg->ver;
	reply->ver_check = msg->ver_check;
	reply->seq = msg->seq;
	reply->type = msg->type;
	reply->func_code = msg->func_code;

	if (msg->type == BB_MSG_REQ) {
		const struct bb_req_msg *req = (struct bb_req_msg *)msg->data;
		struct bb_rsp_msg *rsp = (struct bb_rsp_msg *)reply->data;
		req_handler_t req_handler = get_req_handler(msg);

		reply->type = BB_MSG_RSP;
		if (req_handler) {
			fill_reply_args(req, rsp);
			reply->reply_code = req_handler(req, rsp);
			return reply;
		}
	}

	reply->reply_code = 1;
	reply->payload_len = 0;
	return reply;
}

