/*
 *	Linux LISP:	Locator/ID Separation Protocol
 *
 *			LISP netlink interface
 *
 *	Author: Alex Lorca <alex.lorca@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/netdevice.h>
#include <net/netns/generic.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/lisp.h>

#include "lisp_core.h"

/* family definition */
static struct genl_family lisp_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = LISP_GNL_NAME,
	.version = LISP_GNL_VERSION,
	.maxattr = LISP_GNL_ATTR_MAX,
};

static int lisp_parse_gnlparms(struct genl_info *info, struct map_config *cfg)
{
	struct rloc_entry *re = NULL;
	struct nlattr *att;
	int cnt, err;

	err = -ENOMEM;
	re = kmalloc(sizeof(struct rloc_entry), GFP_KERNEL);
	if (!re)
		goto out;
	INIT_RCU_HEAD(&re->rcu);
	INIT_LIST_HEAD(&re->list);
	INIT_LIST_HEAD(&re->local_list);
	re->weight = 0;
	re->priority = 0;
	cfg->mc_rloc = re;

	/* TODO: sanity check */
	nla_for_each_nested(att, info->attrs[LISP_GNL_ATTR_MAP], cnt) {
		switch(nla_type(att)) {
		case LISP_GNL_ATTR_MAP_EID:
			cfg->mc_dst = nla_get_u32(att);
			break;
		case LISP_GNL_ATTR_MAP_EIDLEN:
			cfg->mc_dst_len = nla_get_u8(att);
			break;
		case LISP_GNL_ATTR_MAP_RLOC:
			re->rloc = ntohl(nla_get_u32(att));
			re->flags = LISP_RLOC_F_REACH;
			break;
		case LISP_GNL_ATTR_MAP_WEIGHT:
			re->weight = nla_get_u8(att);
			break;
		case LISP_GNL_ATTR_MAP_PRIO:
			re->priority = nla_get_u8(att);
			break;
		case LISP_GNL_ATTR_MAP_RLOCF:
			re->flags = nla_get_u8(att);
			re->flags |= LISP_RLOC_F_REACH;
			break;
		}
	}

	cfg->mc_rloc_cnt = 1;
	cfg->mc_map_flags = nla_get_u8(info->attrs[LISP_GNL_ATTR_MAPF]);
	cfg->mc_map_ttl = nla_get_u32(info->attrs[LISP_GNL_ATTR_MAPTTL]);

	return 0;
out:
	return err;
}

static int lisp_gnl_doit_addmap(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct map_config mc;
	int err;

	err = lisp_parse_gnlparms(info, &mc);
	if (err)
		goto out;

	/* The mappings added manually are assumed to be usable
	   and rechable until verification */
	mc.mc_map_flags |= LISP_MAP_F_UP;

	return lisp_map_add(net, &mc);
out:
	return err;
}

static struct genl_ops lisp_gnl_ops_addmap = {
	.cmd = LISP_GNL_CMD_ADDMAP,
	.flags = GENL_ADMIN_PERM,
	.policy = lisp_gnl_policy,
	.doit = lisp_gnl_doit_addmap,
	.dumpit = NULL,
};

static int lisp_gnl_doit_delmap(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct map_config cfg;
	int err;

	err = lisp_parse_gnlparms(info, &cfg);
	if (err)
		goto out;

	pr_debug("LISP: del map eid:%x/%d rloc:%x\n", cfg.mc_dst,
		 cfg.mc_dst_len, cfg.mc_rloc->rloc);

	err = -EINVAL;
	if (cfg.mc_dst == 0 || cfg.mc_dst_len == 0)
		goto out;

	err = lisp_map_del(net, &cfg);
	rloc_free_mem_rcu(cfg.mc_rloc);
out:
	return err;
}

static struct genl_ops lisp_gnl_ops_delmap = {
	.cmd = LISP_GNL_CMD_DELMAP,
	.flags = GENL_ADMIN_PERM,
	.policy = lisp_gnl_policy,
	.doit = lisp_gnl_doit_delmap,
	.dumpit = NULL,
};

static int lisp_gnl_dumpit_showmap(struct sk_buff *skb,
				   struct netlink_callback *cb)
{
	struct net *net = dev_net(skb->dev);
	int err;

	err = lisp_map_show(net, &lisp_gnl_family, skb, cb);

	if (err >= 0)
		return 0;
	else
		return err;
}

static struct genl_ops lisp_gnl_ops_showmap = {
	.cmd = LISP_GNL_CMD_SHOWMAP,
	.flags = 0,
	.policy = lisp_gnl_policy,
	.doit = NULL,
	.dumpit = lisp_gnl_dumpit_showmap,
};

static struct genl_multicast_group lisp_mcgrp = {
	.name = LISP_GNL_MCGRP_NAME,
};

int lisp_nl_init(void)
{
	int err;

	err = genl_register_family(&lisp_gnl_family);
	if (err)
		goto out;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_addmap);
	if (err)
		goto out_unregister_nl;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_delmap);
	if (err)
		goto out_unregister_nl;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_showmap);
	if (err)
		goto out_unregister_nl;

	err = genl_register_mc_group(&lisp_gnl_family, &lisp_mcgrp);
	if (err)
		goto out_unregister_nl;

out:
	return err;
out_unregister_nl:
	genl_unregister_family(&lisp_gnl_family);
	goto out;
}

void lisp_nl_cleanup(void)
{
	genl_unregister_family(&lisp_gnl_family);
}
