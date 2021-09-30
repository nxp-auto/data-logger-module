/*
 * Copyright 2018-2021 NXP
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 */
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/module.h>

#include "pkt_dump.h"

struct pkt_dump_list {
	struct list_head list;
	const struct pkt_dump_ops *ops;
};

DEFINE_MUTEX(g_list_mutex);
LIST_HEAD(g_list_head);

int pkt_dump_reg(const struct pkt_dump_ops *ops)
{
	struct pkt_dump_list *pdump;

	if (!ops)
		return -EINVAL;
	
	mutex_lock(&g_list_mutex);
	list_for_each_entry(pdump, &g_list_head, list) {
		if (pdump->ops == ops) {
			pr_err("pkt_dump: %s has registered", ops->name);
			mutex_unlock(&g_list_mutex);
			return -1;
		}
	}
	pr_info("pkt_dump: reg %s", ops->name);
	pdump = kzalloc(sizeof(struct pkt_dump_list), GFP_KERNEL);
	pdump->ops = ops;
	list_add_tail(&pdump->list, &g_list_head);
	mutex_unlock(&g_list_mutex);
	return 0;
}
EXPORT_SYMBOL(pkt_dump_reg);

void pkt_dump_unreg(const struct pkt_dump_ops *ops)
{
	struct pkt_dump_list *pdump;

	if (!ops)
		return;
	
	mutex_lock(&g_list_mutex);
	list_for_each_entry(pdump, &g_list_head, list) {
		if (pdump->ops == ops) {
			pr_info("pkt_dump: unreg %s", ops->name);
			list_del(&pdump->list);
			kfree(pdump);
			break;
		}
	}
	mutex_unlock(&g_list_mutex);
}
EXPORT_SYMBOL(pkt_dump_unreg);

const struct pkt_dump_ops *pkt_dump_get(const char *name)
{
	struct pkt_dump_list *pdump;
	const struct pkt_dump_ops *ops = NULL;
	
	if (!name)
		return NULL;
	
	mutex_lock(&g_list_mutex);
	list_for_each_entry(pdump, &g_list_head, list) {
		if (strcmp(pdump->ops->name, name) == 0) {
			pr_info("pkt_dump: get %s", name);
			ops = pdump->ops;
			if (ops->owner != THIS_MODULE)
				try_module_get(ops->owner);
			break;
		}
	}
	mutex_unlock(&g_list_mutex);
	return ops;
}

void pkt_dump_put(const struct pkt_dump_ops *ops)
{
	if (ops->owner != THIS_MODULE)
		module_put(ops->owner);
}

