#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>

#include "lisp.h"

/* Exported by map_semantics.c */
extern int map_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct map_result *res, int prefixlen);
extern int release_map(struct map_entry *map);
extern struct map_entry *map_find(struct list_head *meh);

#endif /* _FIB_LOOKUP_H */
