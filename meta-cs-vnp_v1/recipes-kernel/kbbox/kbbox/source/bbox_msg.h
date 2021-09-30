/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#include "bb_msg.h"

#define BBOX_MSG_VER 1

#define BBOX_MSG_FUNC_START_ETHERNET 1 /* To bbox.ko, start capture ethernet packets */
#define BBOX_MSG_FUNC_STOP_ETHERNET  2 /* To bbox.ko, stop capture ethernet packets */
#define BBOX_MSG_FUNC_NEW_ETHERNET   3 /* To bbox.ko, generate a newfile to save packets */
#define BBOX_MSG_FUNC_START_COE      4 /* To bbox.ko, start capture CAN over Ethernet */
#define BBOX_MSG_FUNC_STOP_COE       5 /* To bbox.ko, stop capture CAN over Ethernet */
#define BBOX_MSG_FUNC_NEW_COE        6 /* To bbox.ko, generate a newfile to save CAN packets */
#define BBOX_MSG_FUNC_SET_COE_ARGS   7 /* To bbox.ko, set arguments about CAN over Ethernet */
#define BBOX_MSG_FUNC_START_TRANSFER 8 /* To M7, start sending CAN over Ethernet packets*/
#define BBOX_MSG_FUNC_STOP_TRANSFER  9 /* To M7, stop sending CAN over Ethernet packets*/
#define BBOX_MSG_FUNC_SET_CHANNEL    10
#define BBOX_MSG_FUNC_UPDATE_CHANNEL_BAUDRATE 11
#define BBOX_MSG_FUNC_INIT_FILE      12
#define BBOX_MSG_FUNC_SEND_DIAGNOSIS 13
#define BBOX_MSG_FUNC_OPEN_CAPTURE   14
#define BBOX_MSG_FUNC_CLOSE_CAPTURE  15
#define BBOX_MSG_FUNC_UNINIT_FILE    16

#define BBOX_MSG_NUMBER              17

