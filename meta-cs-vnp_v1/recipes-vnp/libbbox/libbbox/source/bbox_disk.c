/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/*
 * check_disk.c
 */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <fcntl.h>

#include <unistd.h>

#include "lib.h"
#include "bbox_api.h"
#include "bbox_disk.h"

#define MODULE_MESSAGE "[disk]: "

struct partition_entry {
	uint8_t indicator; /* first entry start at 0x1BE, 0x80:active, 0x00: normal */
	uint8_t start_head; /* 0x1BF */
	uint8_t start_sector; /* 0x1C0 bit6-7 is used for cylinder */
	uint8_t start_cylinder; /* 0x1C1 */
	uint8_t system_id; /* 0x1C2 */
	uint8_t end_head;  /* 0x1C3 */
	uint8_t end_sector; /* 0x1C4 bit6-7 is used for cylinder */
	uint8_t end_cylinder; /* 0x1C5 */
	uint32_t relative_sectors; /* 0x1C6 */
	uint32_t total_sectors; /* 0x1CA */
};

#define NEW_PARTITION 0x1
#define NEW_FS 0x2
#define NEW_DM 0x4

struct partition_info {
	bool secure;
	uint32_t new_flags;
	char *target_path;
	const char *fs_fmt;
	uint32_t prt_idx;
};

struct disk_info {
	char *dev_name;
	char *dev_path;
	char *sysblock_path;
	uint32_t total_blocks;
	uint32_t block_size;
	uint32_t prt_num;
	struct partition_info partitions[PARTITION_NUM];
};

uint32_t read_from_file(const char *file)
{
	FILE *fp;
	uint32_t value = 0;
	
	fp = fopen(file, "r");
	int ret = fscanf(fp, "%u", &value);
	(void)ret;
	fclose(fp);
	
	return value;
}

static int init_disk_info(struct disk_info *disk, const char *dev, struct disk_config *config)
{
	int ret;
	char path[256];
	struct stat statbuf;

	if (!config || config->prt_num > PARTITION_NUM)
		return -1;
	
	memset(disk, 0, sizeof(*disk));
	
	if (strncmp(dev, "/dev/", 5) == 0) {
		disk->dev_path = strdup(dev);
		disk->dev_name = strdup(dev+5);
	} else {
		disk->dev_name = strdup(dev);
		disk->dev_path = malloc(strlen(dev) + sizeof("/dev/"));
		sprintf(disk->dev_path, "/dev/%s", dev);
	}
	disk->sysblock_path = malloc(256);
	sprintf(disk->sysblock_path, "/sys/block/%s", disk->dev_name);
	
	disk->prt_num = config->prt_num;
	disk->partitions[0].secure = config->partitions[0].secure;
	disk->partitions[0].fs_fmt = config->partitions[0].fs_fmt;
	disk->partitions[0].prt_idx = config->partitions[0].prt_idx;
	
	if (disk->prt_num > 1) {
		disk->partitions[1].secure = config->partitions[1].secure;
		disk->partitions[1].fs_fmt = config->partitions[1].fs_fmt;
		disk->partitions[1].prt_idx = config->partitions[1].prt_idx;
	}
	
	/* Check if the disk exists */
	if (stat(disk->sysblock_path, &statbuf) == -1) {
		fprintf(stderr, MODULE_MESSAGE "stat %s fail\n", disk->sysblock_path);
		ret = -errno;
		goto FREE;
	}

	assert(snprintf(path, sizeof(path), "%s/size", disk->sysblock_path) < sizeof(path));
	disk->total_blocks = read_from_file(path);
	assert(snprintf(path, sizeof(path), "%s/queue/logical_block_size", disk->sysblock_path) < sizeof(path));
	disk->block_size = read_from_file(path);
	disk->total_blocks /= disk->block_size / 512;
	printf(MODULE_MESSAGE "%s total blocks %u block size %u\n", disk->dev_name, disk->total_blocks,  disk->block_size);
	return 0;
	
FREE:
	free(disk->dev_name);
	free(disk->dev_path);
	free(disk->sysblock_path);
	return ret;
}

static void uinit_disk_info(struct disk_info *disk)
{
	int i;

	for (i = 0; i < disk->prt_num; i++)
		free(disk->partitions[i].target_path);
	
	free(disk->dev_name);
	free(disk->dev_path);
	free(disk->sysblock_path);
}

int write_dpt(struct disk_info *disk)
{
	struct partition_entry entrys[4];
	uint8_t sector_buf[512];
	int fd;
	int i;
	uint32_t start_sector = 32;
	uint32_t total_sectors = (disk->total_blocks - 32) / disk->prt_num;
	
	for (i = 0; i < disk->prt_num; i++) {
		entrys[i].indicator = 0x00;
		entrys[i].start_head = 0x3f;
		entrys[i].start_sector = 0x20 | 0xc0;
		entrys[i].start_cylinder = 0xff;
		entrys[i].system_id = 0x83; /* linux */
		entrys[i].end_head = 0x3f;
		entrys[i].end_sector = 0x20 | 0xc0;
		entrys[i].end_cylinder = 0xff;
		entrys[i].relative_sectors = start_sector;
		entrys[i].total_sectors = ((start_sector + total_sectors) & (~0xff)) - start_sector;
		start_sector += entrys[i].total_sectors;
	}
	entrys[0].start_head = 1;
	entrys[0].start_sector = 1;
	entrys[0].start_cylinder = 0;

	fd  = open(disk->dev_path, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, MODULE_MESSAGE "open %s fail: %s\n", disk->dev_path, strerror(errno));
		return -errno;
	}
	memset(sector_buf, 0, 512);
	memcpy(sector_buf + 512-66, entrys, sizeof(entrys[0]) * disk->prt_num);
	sector_buf[510] = 0x55;
	sector_buf[511] = 0xAA;
	if (write(fd, sector_buf, 512) != 512) {
		fprintf(stderr, MODULE_MESSAGE "write %s fail: %s\n", disk->dev_path, strerror(errno));
		close(fd);
		return -errno;
	}
	fsync(fd);
	close(fd);
	return 0;
}

static int setup_partitions(struct disk_info *disk)
{
	int ret;
	char path[256];
	struct stat sb;
	uint32_t i;
	uint32_t retry_cnt = 3;
	
	RETRY:
		for (i = 0; i < disk->prt_num; i++) {
			assert(snprintf(path, sizeof(path), "%s/%sp%d", disk->sysblock_path, disk->dev_name, 1 + disk->partitions[i].prt_idx) < sizeof(path));
			if (stat(path, &sb) == -1) {
				if (disk->partitions[disk->prt_num - 1].prt_idx != (disk->prt_num - 1)) {
					printf(MODULE_MESSAGE "no partition %s, please check\n", path);
					return -2;
				}
				printf(MODULE_MESSAGE "no partition %s, rewrite MBR\n", path);
				break;
			}
		}
		
		if (i == disk->prt_num) 
			return 0;

		for (i = 0; i < disk->prt_num; i++)
			disk->partitions[i].new_flags |= NEW_PARTITION;
		
		if (retry_cnt-- > 0) {
			if ((ret = write_dpt(disk)))
				return ret;			
			sleep(2);
			goto RETRY;
		}
	
	return -1;
}

int copy_file_with_len(int src_fd, int dest_fd, uint32_t size)
{
	uint8_t block[512];
	uint32_t left_size = size;
	
	while (left_size) {
		const int block_size = left_size > sizeof(block) ? sizeof(block) : left_size;

		if (read(src_fd, block, block_size) != block_size)
			return -1;
		if (write(dest_fd, block, block_size) != block_size)
			return -1;
		left_size -= block_size;
	}
	return size;
}

static void make_path_parents(const char *path)
{
	char *dup_path = strdup(path);
	char *tmp;

    for (tmp = dup_path+1; *tmp; tmp++) {
		if (*tmp == '/') {
			*tmp = 0;
			(void)mkdir(dup_path, S_IRWXU);
			*tmp = '/';
		}
    }	
	free(dup_path);
}

static int generate_key_file(const char *name, uint32_t size)
{
	int fd_r, fd_w;
	int ret;

	make_path_parents(name);
	
	fd_r = open("/dev/urandom", O_RDONLY);
	if (fd_r < 0) {
		fprintf(stderr, MODULE_MESSAGE "open /dev/urandom fail: %s\n", strerror(errno));
		return -errno;
	}
	
	fd_w = open(name, O_CREAT | O_WRONLY, 0600);
	if (fd_w < 0) {
		fprintf(stderr, MODULE_MESSAGE "open %s fail: %s\n", name, strerror(errno));
		close(fd_r);
		return -errno;
	}
	
	ret = copy_file_with_len(fd_r, fd_w, size);
	if (ret == size)
		ret = 0;
	else
		fprintf(stderr, "gen key file:%s fail:%s\n", name, strerror(errno));
	close(fd_r);
	close(fd_w);
	return ret;
}

static int setup_partition_dm(struct disk_info *disk, int prt_no)
{
	char strbuf[256];
	char prt_dev[64];
	char key_file[64];
	struct stat sb;
	int ret;
	int retry_cnt = 3;

	/* get partition name */
	assert(snprintf(prt_dev, sizeof(prt_dev), "%sp%d", disk->dev_name, disk->partitions[prt_no].prt_idx +1) < sizeof(prt_dev));

	/* check key file */
	assert(snprintf(key_file, sizeof(key_file), "/etc/keys/%s", prt_dev) < sizeof(key_file));
	if (stat(key_file, &sb)) {
		fprintf(stderr, MODULE_MESSAGE "No valid key file!\n");
		ret = generate_key_file(key_file, 32);
		if (ret)
			return ret;
	}

	if (disk->partitions[prt_no].new_flags & NEW_PARTITION)
		disk->partitions[prt_no].new_flags |= NEW_DM;
	
	/* check if openend */
	assert(snprintf(strbuf, sizeof(strbuf), "/dev/mapper/%s", prt_dev) < sizeof(strbuf));
	if (stat(strbuf, &sb) == 0)
		return 0; /* already opened */

RETRY:
	if (disk->partitions[prt_no].new_flags & NEW_DM) {
		assert(snprintf(strbuf, sizeof(strbuf), "cryptsetup -d %s luksFormat %sp%d",
			key_file, disk->dev_path, prt_no+1) < sizeof(strbuf));
		ret = bash_command(strbuf);
	}
	/* open */
	assert(snprintf(strbuf, sizeof(strbuf), "cryptsetup -d %s open %sp%d %s", 
		key_file, disk->dev_path, prt_no+1, prt_dev) < sizeof(strbuf));
	ret = bash_command(strbuf);
	if (ret) {
		disk->partitions[prt_no].new_flags |= NEW_DM;
		if (retry_cnt-- > 0)
			goto RETRY;
	}
	return ret;
}

static int setup_dm(struct disk_info *disk)
{
	int i;
	int ret;
	
	for (i = 0; i < disk->prt_num; i++) {
		if (!disk->partitions[i].secure)
			continue;
		ret = setup_partition_dm(disk, i);
		if (ret)
			return ret;
	}
	return 0;
}

static int setup_fs_make(struct disk_info *disk, int prt_no)
{
	char command[256];
	
	if (!disk->partitions[prt_no].secure) {
		assert(snprintf(command, sizeof(command), "mkfs.%s %sp%d", disk->partitions[prt_no].fs_fmt,
			disk->dev_path, disk->partitions[prt_no].prt_idx+1) < sizeof(command));
	} else {
		assert(snprintf(command, sizeof(command), "mkfs.%s /dev/mapper/%sp%d", disk->partitions[prt_no].fs_fmt,
			disk->dev_name, disk->partitions[prt_no].prt_idx+1) < sizeof(command));
	}
	printf(MODULE_MESSAGE "shell: %s\n", command);
	return bash_command(command);
}

static int setup_fs_mount(struct disk_info *disk, int prt_no)
{
	char mount_src[256];
	char mount_target[256];
	int ret;
	
	if (!disk->partitions[prt_no].secure) {
		assert(snprintf(mount_src, sizeof(mount_src), "%sp%d", disk->dev_path, disk->partitions[prt_no].prt_idx+1) < sizeof(mount_src));
		assert(snprintf(mount_target, sizeof(mount_target), "/mnt/%sp%d", disk->dev_name, disk->partitions[prt_no].prt_idx+1) < sizeof(mount_target));
	} else {
		assert(snprintf(mount_src, sizeof(mount_src), "/dev/mapper/%sp%d", disk->dev_name, disk->partitions[prt_no].prt_idx+1) < sizeof(mount_src));
		assert(snprintf(mount_target, sizeof(mount_target), "/mnt/%sp%d_sx", disk->dev_name, disk->partitions[prt_no].prt_idx+1) < sizeof(mount_target));
	}
	disk->partitions[prt_no].target_path = strdup(mount_target);
	
	/* check if already mounted*/
	{
		FILE *fp = fopen("/proc/mounts", "r");
		char line[512];
		
		while(fgets(line, sizeof(line), fp)) {
			char *save;
			char *src = strtok_r(line, " ", &save);
			char *target = strtok_r(NULL, " ", &save);
			char *fmt = strtok_r(NULL, " ", &save);
			bool src_matched = !strcmp(src, mount_src);

			if (src_matched && strcmp(target, mount_target) == 0) {
				if (strcmp(fmt, disk->partitions[prt_no].fs_fmt)) {
					umount(mount_target);
					errno = EINVAL;
					return 1; /* format error, return fail*/
				}
				return 0;
			}
			
			if (src_matched)
				umount(mount_target);	
		}
	}
	
	ret = mkdir(mount_target, 0644);
	if (ret && errno != EEXIST) {
		fprintf(stderr, MODULE_MESSAGE "make dir:%s fail: %s\n", mount_target, strerror(errno));
		return ret;
	}
	
	ret = mount(mount_src, mount_target, disk->partitions[prt_no].fs_fmt, MS_RELATIME, NULL);
	if (ret) {
		fprintf(stderr, MODULE_MESSAGE "mount src:%s target:%s format:%s fail: %s\n",
			mount_src, mount_target, disk->partitions[prt_no].fs_fmt, strerror(errno));
		return ret;
	}
	return 0;
}

static int setup_fs(struct disk_info *disk)
{
	int i;
	int ret;
	int retry_cnt;
	
	for (i = 0; i < disk->prt_num; i++) {
		retry_cnt = 3;
		if (disk->partitions[i].new_flags & (NEW_PARTITION | NEW_DM))
			disk->partitions[i].new_flags |= NEW_FS;

	RETRY:
		if (disk->partitions[i].new_flags & NEW_FS) {
			if ((ret = setup_fs_make(disk, i)))
				return ret;
		}
		
		ret = setup_fs_mount(disk, i);
		if (ret) {
			if (errno == EINVAL && retry_cnt-- > 0) {
				disk->partitions[i].new_flags |= NEW_FS;
				goto RETRY;
			}
			return ret;
		}
	}
	
	return 0;
}

static int setup_bbox_meta(int part, const char *dir)
{
/*
	char path[264];

	(void)snprintf(path, sizeof(path), "%s/journal", dir);
	(void)init_journal(part, path);
*/
	return 0;
}

static int setup_bbox(struct disk_info *disk)
{
	int ret;
	int i;
	char path[256];
	struct stat sb;
	const char *normal_path = NULL;
	const char *secure_path = NULL;
	
	for (i = 0; i < disk->prt_num; i++) {	
		assert(snprintf(path, sizeof(path), "%s/.bb", disk->partitions[i].target_path) < sizeof(path));
		if (stat(path, &sb) == -1
			|| (sb.st_mode & S_IFMT) != S_IFDIR) {
			ret = mkdir(path, 0644);
			if (ret && errno != EEXIST) {
				fprintf(stderr, MODULE_MESSAGE "make dir:%s fail: %s\n", path, strerror(errno));
				return ret;
			}			
		}
		(void)setup_bbox_meta(i, path);

		/* get target path */
		if (disk->partitions[i].secure)
			secure_path = disk->partitions[i].target_path;
		else
			normal_path = disk->partitions[i].target_path;
	}
	
	ret = bbox_file_init(16, normal_path, secure_path, ".bb/log");
	if (ret) {
		fprintf(stderr, MODULE_MESSAGE "bbox_file_init(16, %s, %s) fail=%d\n",
			normal_path ? normal_path : "NULL",
			secure_path ? secure_path : "NULL",
			ret);
	}
	return ret;
}

int bbox_setup_disk(const char *dev, struct disk_config *config)
{
	struct disk_info disk;
	int ret = 0;
	
	if (!dev || !dev[0])
		return -EINVAL;

	ret = init_disk_info(&disk, dev, config);
	if (ret)
		return ret;

	printf(MODULE_MESSAGE "%s\n", disk.dev_path);

	/* Check partitions and mount all partitions */
	ret = setup_partitions(&disk);
	if (ret)
		goto DISK_FREE;

	ret = setup_dm(&disk);
	if (ret)
		goto DISK_FREE;

	ret = setup_fs(&disk);
	if (ret)
		goto DISK_FREE;
	
	/* Setup the disk for use */
	ret = setup_bbox(&disk);
	
DISK_FREE:
	uinit_disk_info(&disk);
	return ret;
}

