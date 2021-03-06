#ifndef _LISP_H
#define _LISP_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/if_tunnel.h>

#define HASH_SIZE        16
#define HASH(addr) (((__force u32)addr^((__force u32)addr>>4))&0xF)

#define MAPGC_DELAY 30 * HZ

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
	unsigned long		jiffies_del;	/* expiration timestamp */
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
	struct timer_list	mapgc_timer;
};

struct lisp_gctimer_data {
	struct net		*net;
	struct lisp_net		*lin;
	long   			args[6];
	void (*cb_fn)(struct map_entry *me, struct lisp_gctimer_data *cb);
};

struct map_config {
	__u16			mc_dst_len;
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


extern int lisp_map_add(struct net *net, struct map_config *cfg);
extern int lisp_map_del(struct net *net, struct map_config *cfg);
extern int lisp_map_show(struct net *net, struct genl_family *gnl_family,
			 struct sk_buff *skb, struct netlink_callback *cb);

/* Exported by map_semantics.c */
extern struct map_entry *map_find(struct list_head *meh);
extern int map_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct map_result *res, int prefixlen);
extern int release_map(struct map_entry *map);
extern int dump_map(struct sk_buff *skb, u32 pid, u32 seq,
		    struct genl_family *family,
		    __be32 dst, int dst_len, struct list_head *rlocs,
		    unsigned int mapf, unsigned long jiffies_exp,
		    unsigned int flags);
extern int release_rloc(struct map_entry *map, struct map_config *cfg);
extern void rloc_free_mem_rcu(struct rloc_entry *rloc);

/* Exported by lisp_netlink.c */
extern int lisp_nl_init(void);
extern void lisp_nl_cleanup(void);
extern void lisp_gnl_notify_cachemiss(struct flowi *fl);


__be32 lisp_rloc_lookup(struct net *net, struct flowi *fl);


#endif /* _LISP_H */
