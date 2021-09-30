/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/netdevice.h>	
#include <net/netlink.h>

#include "bb_netlink.h"
#include "bb_server.h"
#include "eth_pcap.h"
#include "can_ccap.h"
#include "pcap_dump.h"
#include "bbox_file.h"
#include "u2k_thread.h"

struct sock *g_bb_sock;

static void bb_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (void*)skb->data;
	struct nlmsghdr *reply_nlh = NULL;
	struct sk_buff *reply_skb = NULL;
	struct bb_msg *msg = NLMSG_DATA(nlh), *reply_msg = NULL;
	uint32_t size;
	
	if (skb->len < nlh->nlmsg_len)
		return;

	size = bb_get_msg_reply_len(msg);
	if (size) {
		reply_skb = nlmsg_new(size, GFP_KERNEL);
		if (!reply_skb)
			return;
		reply_nlh = (void*)reply_skb->data;
		reply_msg = nlmsg_data(reply_nlh);
		BB_SET_MSG_LEN(reply_msg, size);
	}

	reply_msg = bb_handle_msg(msg, reply_msg);
	if (!reply_msg || !reply_skb) {
		if (reply_skb)
			nlmsg_free(reply_skb);
		return;
	}
	
	nlmsg_put(reply_skb, 0, 0, 0, BB_MSG_LEN(reply_msg), 0);
	NETLINK_CB(reply_skb).portid = 0;
	NETLINK_CB(reply_skb).dst_group = 0; /* not in mcast group */
	
	if (nlmsg_unicast(g_bb_sock, reply_skb, nlh->nlmsg_pid) < 0)
		pr_err("nlmsg_unicast fail");
}

static void bb_client_unbind(struct net *net, int group)
{
	printk("client die");
}

static struct netlink_kernel_cfg bb_netlink_cfg = {
	.input = bb_recv_msg,
	.unbind = bb_client_unbind,
};

static int init_netlink(void)
{
	g_bb_sock = netlink_kernel_create(&init_net, NETLINK_BB, &bb_netlink_cfg);
	if (!g_bb_sock) {
		pr_err("netlink_kernel_create(%d) fail", NETLINK_BB);
		return -1;
	}
	return 0;
}

static void uinit_netlink(void)
{
	netlink_kernel_release(g_bb_sock);
}

static int __init bbox_module_init(void)
{
	int ret = 0;
	
	printk("%s\n", __FUNCTION__);

	init_pcap_dump();
	u2k_init_chrdev();
	init_netlink();
	return ret;
}

static void __exit bbox_module_exit(void)
{
	printk("%s\n", __FUNCTION__);
	
	uinit_netlink();

	close_eth_pcap();
	close_can_ccap();
	uninit_pcap_dump();
	bbox_file_uninit();
	u2k_uninit_chrdev();
}

module_init(bbox_module_init);
module_exit(bbox_module_exit);

MODULE_AUTHOR("NXP Ltd");
MODULE_DESCRIPTION("black box core module");
MODULE_LICENSE("GPL");

