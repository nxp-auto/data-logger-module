/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
/*
 * coe.h
 *
 *  Created on: May 20, 2020
 *      Author: nxf50888
 */

#ifndef COE_H_
#define COE_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1)
struct coe_timestamp_ns {
	uint32_t sec;
	uint32_t nsec;
};

struct coe_timestamp_count {
	uint32_t number;
	uint32_t freq;
};

struct coe_timestamp {
	uint16_t leading; /* leading & 0x8000 ? cnt : t */
	union {
		struct coe_timestamp_ns t;
		struct coe_timestamp_count cnt;
	};
};

enum coe_msg_type {
	COE_MSG_CAN,
	COE_MSG_LIN,
	COE_MSG_CAN_FD
};

struct coe_msg {
	uint16_t /*enum coe_msg_type*/ type;
	struct coe_timestamp ts;	
	uint16_t data_len;
	uint16_t channel_id;
	uint32_t msg_id;
	uint32_t flags;
	uint8_t data[0];
};
#pragma pack()

#define COE_MSG_HDR_LEN (unsigned long)&((struct coe_msg*)0)->data

struct coe_msg *coe_msg_new(uint16_t data_len);

int coe_msg_send(struct coe_msg *coe);

#ifdef __cplusplus
}
#endif
#endif /* COE_H_ */
