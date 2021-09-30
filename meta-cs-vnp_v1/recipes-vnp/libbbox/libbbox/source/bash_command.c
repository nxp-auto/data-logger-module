/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdlib.h>
#include <stdio.h>

#include "lib.h"

#define MODULE_MESSAGE "[lib]: "

int bash_command(const char *cmd)
{
	int ret;

	printf(MODULE_MESSAGE "system(%s)\n", cmd);
	
	ret = system(cmd);
	if (ret < 0) {
		fprintf(stderr, MODULE_MESSAGE "system() fail\n");
		return -1;
	}
	
	if (WIFEXITED(ret)) {
		ret = WEXITSTATUS(ret);
		printf(MODULE_MESSAGE "exit code %d\n", ret);
	} else
		ret = -2; 
	return ret;
}

