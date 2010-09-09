#ifndef _LISP_H
#define _LISP_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/if_tunnel.h>

#define LISP_ENCAPTYPE_UDP 1
#define HASH_SIZE        16
#define HASH(addr) (((__force u32)addr^((__force u32)addr>>4))&0xF)


struct rloc_entry {
	struct list_head	list;
	struct list_head	local_list;
	struct rcu_head		rcu;
	__be32			rloc;
	__u8			priority;
	__u8			weight;
	__u8			flags;
};

struct map_entry {
	struct list_head	list;
	struct rcu_head		rcu;
	__be32			eid;
	__be32			mask;
	struct list_head	rlocs;
	atomic_t		rloc_cnt;
	__u8			flags;
	unsigned long		jiffies;	/* creation timestamp */
	unsigned long		jiffies_exp;	/* expiration timestamp */
};

struct lisp_tunnel {
	struct list_head	list;
	struct net_device	*dev;
	struct ip_tunnel_parm	parms;
};

struct map_table {
	unsigned char tb_data[0];
};

/* TODO: split locking for tunnels and maps */
struct lisp_net {
	spinlock_t		lock; /* Protects tunnels, maps and local_rlocs */
	struct list_head	tunnels[HASH_SIZE];
	struct map_table	*maps;
	struct net_device	*fb_tunnel_dev;	/* Fallback tunnel */
	struct list_head	local_rlocs;
};

struct map_config {
	__u8			mc_dst_len;
	__be32			mc_dst;
	struct rloc_entry	*mc_rloc;
	unsigned int		mc_rloc_cnt;
	__u8			mc_map_flags;
	__u32			mc_map_ttl;	/* mapping ttl (minutes) */
};

struct map_result {
	__u8			prefixlen;
	struct map_entry	*map;
	struct rloc_entry	*rloc;
};

#endif /* _LISP_H */
