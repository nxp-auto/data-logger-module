/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include "bb_server.h"

int bbox_reg_msg_handler(uint32_t msg, req_handler_t func, void *owner);

void bbox_unreg_msg_handler(uint32_t msg, void *owner);

