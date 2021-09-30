/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/*
 * example about dump pcap file
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "u2k_thread.h"


int main(int argc, char *argv[])
{
	int fd;
	struct thread_args args;

	if (argc != 4) {
		printf("No enough argument: <entry_val> <args_val> <thread_val>\n");
		return -1;
	}
	args.entry = strtoul(argv[1], NULL, 16);
	args.arg = strtoul(argv[2], NULL, 16);
	args.thread = strtoul(argv[3], NULL, 16);
	
	fd = open("/dev/" U2K_DEVNAME, O_RDWR);
	if (fd < 0) {
		perror("Open device file");
		return -errno;
	}
	printf("run %lx(%lx, %lx) in kernel\n", args.entry, args.arg, args.thread);
	if (ioctl(fd, IOC_CMD_RUN_THREAD, &args) < 0)
		perror("ioctl");
	printf("end run %lx(%lx, %lx) in kernel\n", args.entry, args.arg, args.thread);
	return 0;
}


