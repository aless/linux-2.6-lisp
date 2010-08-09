/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IPv4 Forwarding Information Base: semantics.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>

#include <net/arp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/nexthop.h>

#include <linux/lisp.h>
#include "map_lookup.h"
#include "lisp.h"

struct map_entry *map_find(struct list_head *meh)
{
	if (meh)
		return list_first_entry_rcu(meh, struct map_entry, list);
	return NULL;
}

struct rloc_entry *rloc_find(struct list_head *reh)
{
	if (reh)
		return list_first_entry_rcu(reh, struct rloc_entry, list);
	return NULL;
}

int map_semantic_match(struct list_head *head, const struct flowi *flp,
		       struct map_result *res, int prefixlen)
{
	struct map_entry *me;
	struct rloc_entry *re;

	if (head)
	{
		me = map_find(head);
		re = rloc_find(&me->rlocs);

		printk(KERN_INFO "%s match rloc:%x\n", __func__, htonl(re->rloc));
		goto out_fill_res;
	}
	else
		return 1;

out_fill_res:
	res->prefixlen = prefixlen;
	res->rloc = re;
	return 0;
}

static void __rloc_free_mem(struct rcu_head *head)
{
	struct rloc_entry *rloc = container_of(head, struct rloc_entry, rcu);
	kfree(rloc);
}

static void rloc_free_mem_rcu(struct rloc_entry *rloc)
{
	call_rcu(&rloc->rcu, __rloc_free_mem);
}

int release_map(struct map_entry *map)
{
	struct rloc_entry *rloc, *rtmp;
	int found = 0;
	int cnt = atomic_read(&map->rloc_cnt);

	if (cnt > 0) {
		list_for_each_entry_safe(rloc, rtmp, &map->rlocs, list) {
			printk(KERN_INFO "%s rloc:%x (%p)\n", __func__, htonl(rloc->rloc), rloc);
			list_del_rcu(&rloc->list);
			rloc_free_mem_rcu(rloc);
			found++;
		}
	}
	return found;
}
