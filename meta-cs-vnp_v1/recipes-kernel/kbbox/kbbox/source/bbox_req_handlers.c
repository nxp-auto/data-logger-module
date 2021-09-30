/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>

#include "bb_server.h"
#include "bbox_msg.h"
#include "bbox_api.h"

static
uint16_t bbox_open_capture_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 2
		|| req->args[0].type != BB_ARG_VALUE
		|| req->args[1].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_open_capture(req->args[0].val, REQ_MSG_ARG_PTR(req, 1));
	return 0;
}

static
uint16_t bbox_close_capture_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 1
		|| req->args[0].type != BB_ARG_VALUE)
		return 2;
	
	rsp->func_ret = bbox_close_capture(req->args[0].val);
	return 0;
}

static
uint16_t bbox_start_dump_ethernet_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 3
		|| req->args[0].type != BB_ARG_POINTER_IN
		|| req->args[1].type != BB_ARG_VALUE
		|| req->args[2].type != BB_ARG_VALUE)
		return 2;
	
	rsp->func_ret = bbox_start_dump_ethernet(REQ_MSG_ARG_PTR(req, 0), 
				req->args[1].val,
				req->args[2].val);
	return 0;
}

static
uint16_t bbox_stop_dump_ethernet_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 1
		|| req->args[0].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_stop_dump_ethernet(REQ_MSG_ARG_PTR(req, 0));
	return 0;
}

static
uint16_t bbox_new_ethernet_dump_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 1
		|| req->args[0].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_new_ethernet_dump(REQ_MSG_ARG_PTR(req, 0));
	return 0;
}

static
uint16_t bbox_start_dump_coe_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 3
		|| req->args[0].type != BB_ARG_POINTER_IN
		|| req->args[1].type != BB_ARG_VALUE
		|| req->args[2].type != BB_ARG_VALUE)
		return 2;
	
	rsp->func_ret = bbox_start_dump_coe(REQ_MSG_ARG_PTR(req, 0), 
				req->args[1].val,
				req->args[2].val);
	return 0;
}

static
uint16_t bbox_stop_dump_coe_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 1
		|| req->args[0].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_stop_dump_coe(REQ_MSG_ARG_PTR(req, 0));
	return 0;
}

static
uint16_t bbox_new_coe_dump_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 1
		|| req->args[0].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_new_coe_dump(REQ_MSG_ARG_PTR(req, 0));
	return 0;
}

static
uint16_t bbox_set_coe_args_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 2
		|| req->args[0].type != BB_ARG_VALUE
		|| req->args[1].type != BB_ARG_VALUE)
		return 2;
	
	rsp->func_ret = bbox_set_coe_args((uint16_t)req->args[0].val, (uint16_t)req->args[1].val);
	return 0;
}

static
uint16_t bbox_file_init_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 4
		|| req->args[0].type != BB_ARG_VALUE
		|| req->args[1].type != BB_ARG_POINTER_IN
		|| req->args[2].type != BB_ARG_POINTER_IN
		|| req->args[3].type != BB_ARG_POINTER_IN)
		return 2;
	
	rsp->func_ret = bbox_file_init(req->args[0].val, 
							REQ_MSG_ARG_PTR(req, 1), 
							REQ_MSG_ARG_PTR(req, 2), 
							REQ_MSG_ARG_PTR(req, 3));
	return 0;
}

static
uint16_t bbox_file_uninit_req(const struct bb_req_msg *req, struct bb_rsp_msg *rsp)
{
	if (req->argc != 0)
		return 2;
	
	rsp->func_ret = 0;
	bbox_file_uninit();
	return 0;
}

static req_handler_t g_bbox_req_handlers[BBOX_MSG_NUMBER] = {
	[BBOX_MSG_FUNC_START_ETHERNET] = bbox_start_dump_ethernet_req,
	[BBOX_MSG_FUNC_STOP_ETHERNET]  = bbox_stop_dump_ethernet_req,
	[BBOX_MSG_FUNC_NEW_ETHERNET]   = bbox_new_ethernet_dump_req,
	[BBOX_MSG_FUNC_START_COE]      = bbox_start_dump_coe_req,
	[BBOX_MSG_FUNC_STOP_COE]       = bbox_stop_dump_coe_req,
	[BBOX_MSG_FUNC_NEW_COE]        = bbox_new_coe_dump_req,
	[BBOX_MSG_FUNC_SET_COE_ARGS]   = bbox_set_coe_args_req,
	[BBOX_MSG_FUNC_SET_CHANNEL]    = NULL, /* need to be registered */
	[BBOX_MSG_FUNC_INIT_FILE]      = bbox_file_init_req,
	[BBOX_MSG_FUNC_OPEN_CAPTURE]   = bbox_open_capture_req,
	[BBOX_MSG_FUNC_CLOSE_CAPTURE]  = bbox_close_capture_req,
	[BBOX_MSG_FUNC_UNINIT_FILE]    = bbox_file_uninit_req,
};

req_handler_t bb_req_handler(const struct bb_msg *msg)
{
	if (msg->ver == BBOX_MSG_VER
		&& msg->func_code < ARRAY_SIZE(g_bbox_req_handlers))
		return g_bbox_req_handlers[msg->func_code];

	return NULL;
}

int bbox_reg_msg_handler(uint32_t msg, req_handler_t func, void *owner)
{
	if (msg < ARRAY_SIZE(g_bbox_req_handlers)) {
		g_bbox_req_handlers[msg] = func;
		return 0;
	}
	
	return -EINVAL;
}
EXPORT_SYMBOL(bbox_reg_msg_handler);

void bbox_unreg_msg_handler(uint32_t msg, void *owner)
{
	if (msg < ARRAY_SIZE(g_bbox_req_handlers)) {
		g_bbox_req_handlers[msg] = NULL;
	}
}
EXPORT_SYMBOL(bbox_unreg_msg_handler);

