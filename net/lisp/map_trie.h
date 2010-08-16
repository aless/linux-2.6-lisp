#include <linux/skbuff.h>
#include <net/flow.h>
#include <net/genetlink.h>

#include "lisp.h"

extern void map_hash_init(void);
extern struct map_table *map_hash_table(void);
extern int map_table_insert(struct map_table *tb, struct map_config *cfg);
extern int map_table_delete(struct map_table *tb, struct map_config *cfg);
extern int map_table_lookup(struct map_table *tb, const struct flowi *flp,
			    struct map_result *res);
extern int map_table_flush(struct map_table *tb);
extern int map_table_dump(struct map_table *tb, struct genl_family *family,
			  struct sk_buff *skb, struct netlink_callback *cb);
