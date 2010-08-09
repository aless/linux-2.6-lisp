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
	struct rcu_head		rcu;
	__be32			rloc;
	int			priority;
	int			weight;
	unsigned char		flags;
};

struct map_entry {
	struct list_head	list;
	struct rcu_head		rcu;
	__be32			eid;
	__be32			mask;
	struct list_head	rlocs;
	atomic_t		rloc_cnt;
	unsigned char		flags;
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
	spinlock_t		lock; /* Protects tunnels and maps */
	struct list_head	tunnels[HASH_SIZE];
	struct map_table	*maps;
	struct net_device	*fb_tunnel_dev;	/* Fallback tunnel */
};

struct map_config {
	u8			mc_dst_len;
	__be32			mc_dst;
	struct list_head	mc_rlocs;
	int			mc_rloc_cnt;
	unsigned char		mc_map_flags;
};

struct map_result {
	unsigned char		prefixlen;
	struct rloc_entry	*rloc;
};

#endif /* _LISP_H */
