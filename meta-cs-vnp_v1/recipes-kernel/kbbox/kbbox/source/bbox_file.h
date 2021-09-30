/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
int bbox_file_init(unsigned int max_num, const char *path, const char *secure_path, const char *log_filename);
void bbox_file_uninit(void);

#ifdef __KERNEL__
struct bbox_ioctx;
int bbox_file_create_ioctx(struct bbox_ioctx **ioctx);
void bbox_file_destory_ioctx(struct bbox_ioctx *ioctx);

struct bbox_file *bbox_file_open(const char *filename, int flags);
int bbox_file_write(struct bbox_file *bfile, const void *buff, unsigned int size);
int bbox_file_close(struct bbox_file *bfile);
uint64_t bbox_file_pos(struct bbox_file *bfile);
#endif

#ifdef __cplusplus
}
#endif

