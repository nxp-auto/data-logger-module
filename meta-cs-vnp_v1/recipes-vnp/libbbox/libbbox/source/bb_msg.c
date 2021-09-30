/*
 * Copyright 2018-2021 NXP
 * All rights reserved.
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
/*
 * bb_msg.c
 */
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <errno.h>

#include "bb_msg_client.h"

struct bb_netlink_args {
	pid_t src_pid;
	uint32_t src_group;
	pid_t dest_pid;
	uint32_t dest_group;
};

struct bb_sock_client {
	int sockfd;
	sa_family_t family;
	int protocol;
	int rsp_timeout;
	union {
		struct bb_netlink_args netlink;
		struct bb_udp_args udp;
	};
	uint16_t req_seq;
	int cmd_buf_len;
	void *cmd_buf;
};

struct bb_client {
	const struct bb_msg_ops *ops;
	uint8_t extend[0];
};

void *alloc_client(int extend_size)
{
	return calloc(sizeof(struct bb_client) + extend_size, 1);
}

static struct bb_msg *netlink_get_msg_buff(bb_client_t client, uint32_t payload_len)
{
	struct bb_client *clientp = client;
	struct bb_sock_client *soc = (void*)clientp->extend;
	const uint32_t total_len = NLMSG_HDRLEN + BB_MSG_HDRLEN + payload_len;
	
	if (total_len > soc->cmd_buf_len) {
		free(soc->cmd_buf);
		soc->cmd_buf = malloc(total_len);
		soc->cmd_buf_len = total_len;
	}
	return soc->cmd_buf + NLMSG_HDRLEN;
}

static void netlink_put_msg_buff(bb_client_t client, struct bb_msg *msg)
{
	return;
}

static int netlink_do_req(bb_client_t client, struct bb_msg *msg)
{
	struct bb_client *clientp = client;
	struct bb_sock_client *soc = (void*)clientp->extend;
	struct msghdr msg_hdr = {0};
	struct sockaddr_nl dest_addr;
	struct iovec iov;
	struct nlmsghdr *nlh = (void*)msg - NLMSG_HDRLEN;
	const int msg_len = BB_MSG_HDRLEN + msg->payload_len;

	msg->seq = ++soc->req_seq;
	
	nlh->nlmsg_len = NLMSG_HDRLEN + msg_len;
	nlh->nlmsg_pid = soc->netlink.src_pid;
	nlh->nlmsg_flags = 0;

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;

	dest_addr.nl_family = soc->family;
	dest_addr.nl_pid = soc->netlink.dest_pid;
	dest_addr.nl_groups = soc->netlink.dest_group;
	
	msg_hdr.msg_name = (void *)&dest_addr;
	msg_hdr.msg_namelen = sizeof(dest_addr);
	msg_hdr.msg_iov = &iov;
	msg_hdr.msg_iovlen = 1;
	if (sendmsg(soc->sockfd, &msg_hdr, 0) == -1) {
		fprintf(stderr, "netlink sendmsg() fail:%s\n", strerror(errno));
		return -errno;
	}

	msg_hdr.msg_iov->iov_len = soc->cmd_buf_len;
	do {
		if (recvmsg(soc->sockfd, &msg_hdr, 0) == -1) {
			fprintf(stderr, "netlink recvmsg() fail:%s\n", strerror(errno));
			return -errno;
		}
	} while (msg->seq != soc->req_seq);

	return 0;
}

static void socket_msg_close(bb_client_t client)
{
	struct bb_client *clientp = alloc_client(sizeof(struct bb_sock_client));
	struct bb_sock_client *soc = (void*)clientp->extend;

	close(soc->sockfd);
	free(soc->cmd_buf);
	free(client);
}

static const struct bb_msg_ops g_msg_netlink_ops = {
	.get_msg_buff = netlink_get_msg_buff,
	.put_msg_buff = netlink_put_msg_buff,
	.do_req = netlink_do_req,
	.close = socket_msg_close,
};

int bb_msg_open_netlink(bb_client_t *pclient, int src_pid, int dest_pid, int protocol)
{
	struct bb_client *client = alloc_client(sizeof(struct bb_sock_client));
	struct bb_sock_client *soc = (void*)client->extend;
	struct sockaddr_nl src_addr;
	struct timeval time;
	
	if (!client)
		return -ENOMEM;

	if (src_pid < 0) {
		free(client);
		return -EINVAL;
	}
	
	client->ops = &g_msg_netlink_ops;
	
	soc->netlink.src_pid = src_pid;
	soc->netlink.src_group = 0;
	soc->netlink.dest_pid = dest_pid;
	soc->netlink.dest_group = 0;

	soc->rsp_timeout = 3;
	soc->req_seq = 100;
	soc->cmd_buf_len = 1400;
	soc->cmd_buf = malloc(soc->cmd_buf_len);
	
	soc->family = AF_NETLINK;
	soc->protocol = protocol;
	soc->sockfd = socket(soc->family, SOCK_RAW, soc->protocol);
	if (soc->sockfd < 0) {
		fprintf(stderr, "socket(AF_NETLINK, SOCK_RAW, %d) fail:%s\n", soc->protocol, strerror(errno));
		free(client);
		return -errno;
	}
	
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = soc->family;
	src_addr.nl_pid = soc->netlink.src_pid;
	src_addr.nl_groups = soc->netlink.src_group;
	if (bind(soc->sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
		fprintf(stderr, "bind(%d) fail:%s\n", soc->sockfd, strerror(errno));
		close(soc->sockfd);
		free(soc->cmd_buf);
		free(client);
		return -errno;
	}

	
	if (soc->netlink.src_pid == 0) {
		/* get allocated pid */
		socklen_t size;
		
		if(-1 == getsockname(soc->sockfd, (struct sockaddr *)&src_addr, &size)) {
			fprintf(stderr, "getsockname() fail: %s\n", strerror(errno));
			return -errno;
		}
		printf("netlink get source pid %d\n", soc->netlink.src_pid);
		soc->netlink.src_pid = src_addr.nl_pid;
	}

	/* set timeout */
	if (soc->rsp_timeout) {
		time.tv_sec = soc->rsp_timeout;
		time.tv_usec = 0;
		setsockopt(soc->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));
	}

	*pclient = client;
	return 0;
}


static struct bb_msg *udp_get_msg_buff(bb_client_t client, uint32_t payload_len)
{
	struct bb_client *clientp = client;
	struct bb_sock_client *soc = (void*)clientp->extend;
	const uint32_t total_len = BB_MSG_HDRLEN + payload_len;
	
	if (total_len > soc->cmd_buf_len) {
		free(soc->cmd_buf);
		soc->cmd_buf = malloc(total_len);
		soc->cmd_buf_len = total_len;
	}
	return soc->cmd_buf;
}

static void udp_put_msg_buff(bb_client_t client, struct bb_msg *msg)
{
	return;
}

static int udp_do_req(bb_client_t client, struct bb_msg *msg)
{
	struct bb_client *clientp = client;
	struct bb_sock_client *soc = (void*)clientp->extend;
	struct msghdr msg_hdr = {0};
	struct sockaddr_in dest_addr;
	struct iovec iov;
	const int msg_len = BB_MSG_HDRLEN + msg->payload_len;

	msg->seq = ++soc->req_seq;
	
	iov.iov_base = msg;
	iov.iov_len = msg_len;

	bzero(&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = soc->family;
	dest_addr.sin_port = htons(soc->udp.dest_port);
	dest_addr.sin_addr.s_addr = htonl(soc->udp.dest_ip);
	
	msg_hdr.msg_name = (void *)&dest_addr;
	msg_hdr.msg_namelen = sizeof(dest_addr);
	msg_hdr.msg_iov = &iov;
	msg_hdr.msg_iovlen = 1;
	if (sendmsg(soc->sockfd, &msg_hdr, 0) == -1) {
		fprintf(stderr, "udp sendmsg() fail:%s\n", strerror(errno));
		return -errno;
	}

	msg_hdr.msg_iov->iov_len = soc->cmd_buf_len;
	do {
		if (recvmsg(soc->sockfd, &msg_hdr, 0) == -1) {
			fprintf(stderr, "udp recvmsg() fail:%s\n", strerror(errno));
			return -errno;
		}
	} while (msg->seq != soc->req_seq);

	return 0;
}

static const struct bb_msg_ops g_msg_udp_ops = {
	.get_msg_buff = udp_get_msg_buff,
	.put_msg_buff = udp_put_msg_buff,
	.do_req = udp_do_req,
	.close = socket_msg_close,
};

int bb_msg_open_udp(bb_client_t *pclient, struct bb_udp_args *args)
{
	struct bb_client *client = alloc_client(sizeof(struct bb_sock_client));
	struct bb_sock_client *soc = (void*)client->extend;
	struct timeval time;

	if (!client)
		return -ENOMEM;

	if (!args) {
		free(client);
		return -EINVAL;
	}
	
	client->ops = &g_msg_udp_ops;

	soc->udp = *args;

	soc->rsp_timeout = 2;
	soc->req_seq = 100;
	soc->cmd_buf_len = 1400;
	soc->cmd_buf = malloc(soc->cmd_buf_len);
	
	soc->family = AF_INET;
	soc->protocol = 0;
	soc->sockfd = socket(soc->family, SOCK_DGRAM, soc->protocol);
	if (soc->sockfd < 0) {
		fprintf(stderr, "socket(AF_INET, SOCK_DGRAM, %d) fail:%s\n", soc->protocol, strerror(errno));
		free(soc->cmd_buf);
		free(client);
		return -errno;
	}

	/* set timeout */
	if (soc->rsp_timeout) {
		time.tv_sec = soc->rsp_timeout;
		time.tv_usec = 0;
		setsockopt(soc->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time, sizeof(time));
	}

	*pclient = client;
	return 0;
}

int bb_msg_close(bb_client_t client)
{
	struct bb_client *clientp = client;

	if (!client)
		return -EINVAL;
	if (clientp->ops->close)
		clientp->ops->close(client);
	return 0;
}

/*
 * msghdr--> iovec --> nlmsghdr + bb_msg + bb_req_msg + args + data
*/
int bb_msg_req(bb_client_t client, uint16_t func_code, uint16_t argc, struct bb_arg args[], int *ret)
{
	struct bb_client *clientp = client;
	struct bb_msg *msg;
	struct bb_req_msg *req_msg;
	struct bb_rsp_msg *rsp_msg;
	int msg_payload_len;
	int i, j;
	int offset = 0;
	uint8_t *data;
	int req_rc;
	
	if (!client)
		return -EINVAL;

	/* get payload len */
	msg_payload_len = (long)&((struct bb_req_msg*)0)->args[argc];
	for (i = 0; i < argc; i++) {
		if (args[i].type & BB_ARG_POINTER_IN)
			msg_payload_len += args[i].len;
	}
	
	msg = clientp->ops->get_msg_buff(clientp, msg_payload_len);	

	msg->ver = 0x1;
	msg->ver_check = 0xfe - msg->ver;
	msg->seq = 0;
	msg->type = BB_MSG_REQ;
	msg->func_code = func_code;
	msg->payload_len = msg_payload_len;
	
	req_msg = (void*)msg->data;
	req_msg->argc = argc;
	
	offset = 0;
	data = (uint8_t*)&req_msg->args[argc];
	for (i = 0; i < argc; i++) {
		req_msg->args[i].type = args[i].type;
		req_msg->args[i].len = args[i].len;
		if (args[i].type & BB_ARG_POINTER_MASK) {
			req_msg->args[i].val = offset;
			if (args[i].type & BB_ARG_POINTER_IN && args[i].len) {
				memcpy(data + offset, args[i].ptr, args[i].len);
				offset += args[i].len;
			}
		} else
			req_msg->args[i].val = args[i].val;
	}

	req_rc = clientp->ops->do_req(clientp, msg);
	if (req_rc)
		return req_rc;
	
	if ((req_rc = msg->reply_code)) {
		fprintf(stderr, "client error: %d\n", req_rc);
		clientp->ops->put_msg_buff(clientp, msg);
		return req_rc;
	}

	rsp_msg = (struct bb_rsp_msg*)msg->data;
	if (ret)
		*ret = rsp_msg->func_ret;
	
	offset = 0;
	data = (uint8_t*)rsp_msg->args + rsp_msg->argc * sizeof(struct bb_msg_arg);
	for (i = 0, j = 0; i < argc; i++) {
		if (args[i].type & BB_ARG_POINTER_OUT) {
			if (args[i].len)
				memcpy(args[i].ptr, data + offset, rsp_msg->args[j].len);
			j++;
		}
	}
	clientp->ops->put_msg_buff(clientp, msg);
	return 0;
}


