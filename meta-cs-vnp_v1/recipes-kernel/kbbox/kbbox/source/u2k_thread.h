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
#include <stdbool.h>
#endif
#ifdef ___cplusplus
extern "C" {
#endif

#define U2K_DEVNAME "u2k"

enum U2K_IOC_CMD {
	IOC_CMD_RUN_THREAD = 0xff000000
};

struct thread_args {
	uint64_t entry;
	uint64_t arg;
	uint64_t thread;
};

#ifdef __KERNEL__
int u2k_init_chrdev(void);
void u2k_uninit_chrdev(void);
struct u2k_thread *u2k_thread_run(unsigned long entry, unsigned long args);
int u2k_thread_stop(struct u2k_thread *thread);
bool u2k_thread_should_stop(struct u2k_thread *thread);

#endif
#ifdef ___cplusplus
}
#endif
