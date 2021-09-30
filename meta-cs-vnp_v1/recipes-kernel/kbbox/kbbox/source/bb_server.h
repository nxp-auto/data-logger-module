/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include "bb_msg.h"

#ifdef ___cplusplus
extern "C" {
#endif

uint32_t bb_get_msg_reply_len(const struct bb_msg *msg);

/*
 * entry function for all message, called when message arrived.
 * @reply: reply message buff
 * @return : reply message, don't need reply if it is null
 */
struct bb_msg *bb_handle_msg(const struct bb_msg *msg, struct bb_msg *reply);

/*
 * @return: return code of bb_msg, 0 is success
 */
typedef uint16_t (*req_handler_t)(const struct bb_req_msg *req, struct bb_rsp_msg *rsp);

/*
 * This function is called by bb_handle_msg(), implemented by user
 */
req_handler_t bb_req_handler(const struct bb_msg *msg);
#ifdef ___cplusplus
}
#endif

