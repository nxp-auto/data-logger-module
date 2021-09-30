/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

struct partition_config {
	bool secure;
	const char *fs_fmt;
	uint32_t prt_idx;
};

#define PARTITION_NUM 2
struct disk_config {
	uint32_t prt_num;
	struct partition_config partitions[PARTITION_NUM];
};

int bbox_setup_disk(const char *dev, struct disk_config *config);
#ifdef __cplusplus
}
#endif
