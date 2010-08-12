/*
 *	Linux LISP:	Locator/ID Separation Protocol
 *
 *			EID-to-RLOC database and cache. This code is directly
 *			adapted from fib_trie.
 *
 *	Author: Alex Lorca <alex.lorca@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#define VERSION "0.409"

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
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
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/sock.h>

#include <net/netlink.h>
#include <net/genetlink.h>
#include "map_lookup.h"
#include "lisp.h"

#define MAX_STAT_DEPTH 32

#define KEYLENGTH (8*sizeof(t_key))

typedef unsigned int t_key;

#define T_TNODE 0
#define T_LEAF  1
#define NODE_TYPE_MASK	0x1UL
#define NODE_TYPE(node) ((node)->parent & NODE_TYPE_MASK)

#define IS_TNODE(n) (!(n->parent & T_LEAF))
#define IS_LEAF(n) (n->parent & T_LEAF)

struct node {
	unsigned long parent;
	t_key key;
};

struct leaf {
	unsigned long parent;
	t_key key;
	struct hlist_head list;
	struct rcu_head rcu;
};

struct leaf_info {
	struct hlist_node hlist;
	struct rcu_head rcu;
	int plen;
	struct list_head datalh;
};

struct tnode {
	unsigned long parent;
	t_key key;
	unsigned char pos;		/* 2log(KEYLENGTH) bits needed */
	unsigned char bits;		/* 2log(KEYLENGTH) bits needed */
	unsigned int full_children;	/* KEYLENGTH bits needed */
	unsigned int empty_children;	/* KEYLENGTH bits needed */
	union {
		struct rcu_head rcu;
		struct work_struct work;
		struct tnode *tnode_free;
	};
	struct node *child[0];
};

struct trie_stat {
	unsigned int totdepth;
	unsigned int maxdepth;
	unsigned int tnodes;
	unsigned int leaves;
	unsigned int nullpointers;
	unsigned int prefixes;
	unsigned int nodesizes[MAX_STAT_DEPTH];
};

struct trie {
	struct node *trie;
};

static void put_child(struct trie *t, struct tnode *tn, int i, struct node *n);
static void tnode_put_child_reorg(struct tnode *tn, int i, struct node *n,
				  int wasfull);
static struct node *resize(struct trie *t, struct tnode *tn);
static struct tnode *inflate(struct trie *t, struct tnode *tn);
static struct tnode *halve(struct trie *t, struct tnode *tn);
/* tnodes to free after resize(); protected by RTNL */
static struct tnode *tnode_free_head;
static size_t tnode_free_size;

/*
 * synchronize_rcu after call_rcu for that many pages; it should be especially
 * useful before resizing the root node with PREEMPT_NONE configs; the value was
 * obtained experimentally, aiming to avoid visible slowdown.
 */
static const int sync_pages = 128;

static struct kmem_cache *map_entry_kmem __read_mostly;
static struct kmem_cache *trie_leaf_kmem __read_mostly;

static inline struct tnode *node_parent(struct node *node)
{
	return (struct tnode *)(node->parent & ~NODE_TYPE_MASK);
}

static inline struct tnode *node_parent_rcu(struct node *node)
{
	struct tnode *ret = node_parent(node);

	return rcu_dereference(ret);
}

/* Same as rcu_assign_pointer
 * but that macro() assumes that value is a pointer.
 */
static inline void node_set_parent(struct node *node, struct tnode *ptr)
{
	smp_wmb();
	node->parent = (unsigned long)ptr | NODE_TYPE(node);
}

static inline struct node *tnode_get_child(struct tnode *tn, unsigned int i)
{
	BUG_ON(i >= 1U << tn->bits);

	return tn->child[i];
}

static inline struct node *tnode_get_child_rcu(struct tnode *tn, unsigned int i)
{
	struct node *ret = tnode_get_child(tn, i);

	return rcu_dereference_check(ret,
				     rcu_read_lock_held() ||
				     lockdep_rtnl_is_held());
}

static inline int tnode_child_length(const struct tnode *tn)
{
	return 1 << tn->bits;
}

static inline t_key mask_pfx(t_key k, unsigned short l)
{
	return (l == 0) ? 0 : k >> (KEYLENGTH-l) << (KEYLENGTH-l);
}

static inline t_key tkey_extract_bits(t_key a, int offset, int bits)
{
	if (offset < KEYLENGTH)
		return ((t_key)(a << offset)) >> (KEYLENGTH - bits);
	else
		return 0;
}

static inline int tkey_equals(t_key a, t_key b)
{
	return a == b;
}

static inline int tkey_sub_equals(t_key a, int offset, int bits, t_key b)
{
	if (bits == 0 || offset >= KEYLENGTH)
		return 1;
	bits = bits > KEYLENGTH ? KEYLENGTH : bits;
	return ((a ^ b) << offset) >> (KEYLENGTH - bits) == 0;
}

static inline int tkey_mismatch(t_key a, int offset, t_key b)
{
	t_key diff = a ^ b;
	int i = offset;

	if (!diff)
		return 0;
	while ((diff << i) >> (KEYLENGTH-1) == 0)
		i++;
	return i;
}

/*
  To understand this stuff, an understanding of keys and all their bits is
  necessary. Every node in the trie has a key associated with it, but not
  all of the bits in that key are significant.

  Consider a node 'n' and its parent 'tp'.

  If n is a leaf, every bit in its key is significant. Its presence is
  necessitated by path compression, since during a tree traversal (when
  searching for a leaf - unless we are doing an insertion) we will completely
  ignore all skipped bits we encounter. Thus we need to verify, at the end of
  a potentially successful search, that we have indeed been walking the
  correct key path.

  Note that we can never "miss" the correct key in the tree if present by
  following the wrong path. Path compression ensures that segments of the key
  that are the same for all keys with a given prefix are skipped, but the
  skipped part *is* identical for each node in the subtrie below the skipped
  bit! trie_insert() in this implementation takes care of that - note the
  call to tkey_sub_equals() in trie_insert().

  if n is an internal node - a 'tnode' here, the various parts of its key
  have many different meanings.

  Example:
  _________________________________________________________________
  | i | i | i | i | i | i | i | N | N | N | S | S | S | S | S | C |
  -----------------------------------------------------------------
    0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15

  _________________________________________________________________
  | C | C | C | u | u | u | u | u | u | u | u | u | u | u | u | u |
  -----------------------------------------------------------------
   16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31

  tp->pos = 7
  tp->bits = 3
  n->pos = 15
  n->bits = 4

  First, let's just ignore the bits that come before the parent tp, that is
  the bits from 0 to (tp->pos-1). They are *known* but at this point we do
  not use them for anything.

  The bits from (tp->pos) to (tp->pos + tp->bits - 1) - "N", above - are the
  index into the parent's child array. That is, they will be used to find
  'n' among tp's children.

  The bits from (tp->pos + tp->bits) to (n->pos - 1) - "S" - are skipped bits
  for the node n.

  All the bits we have seen so far are significant to the node n. The rest
  of the bits are really not needed or indeed known in n->key.

  The bits from (n->pos) to (n->pos + n->bits - 1) - "C" - are the index into
  n's child array, and will of course be different for each child.


  The rest of the bits, from (n->pos + n->bits) onward, are completely unknown
  at this point.

*/

static inline void check_tnode(const struct tnode *tn)
{
	WARN_ON(tn && tn->pos+tn->bits > 32);
}

static const int halve_threshold = 25;
static const int inflate_threshold = 50;
static const int halve_threshold_root = 15;
static const int inflate_threshold_root = 30;

static void __map_free_mem(struct rcu_head *head)
{
	struct map_entry *m = container_of(head, struct map_entry, rcu);
	kmem_cache_free(map_entry_kmem, m);
}

static inline void map_free_mem_rcu(struct map_entry *me)
{
	call_rcu(&me->rcu, __map_free_mem);
}

static void __leaf_free_rcu(struct rcu_head *head)
{
	struct leaf *l = container_of(head, struct leaf, rcu);
	kmem_cache_free(trie_leaf_kmem, l);
}

static inline void free_leaf(struct leaf *l)
{
	call_rcu_bh(&l->rcu, __leaf_free_rcu);
}

static void __leaf_info_free_rcu(struct rcu_head *head)
{
	kfree(container_of(head, struct leaf_info, rcu));
}

static inline void free_leaf_info(struct leaf_info *leaf)
{
	call_rcu(&leaf->rcu, __leaf_info_free_rcu);
}

static struct tnode *tnode_alloc(size_t size)
{
	if (size <= PAGE_SIZE)
		return kzalloc(size, GFP_KERNEL);
	else
		return __vmalloc(size, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
}

static void __tnode_vfree(struct work_struct *arg)
{
	struct tnode *tn = container_of(arg, struct tnode, work);
	vfree(tn);
}

static void __tnode_free_rcu(struct rcu_head *head)
{
	struct tnode *tn = container_of(head, struct tnode, rcu);
	size_t size = sizeof(struct tnode) +
		      (sizeof(struct node *) << tn->bits);

	if (size <= PAGE_SIZE)
		kfree(tn);
	else {
		INIT_WORK(&tn->work, __tnode_vfree);
		schedule_work(&tn->work);
	}
}

static inline void tnode_free(struct tnode *tn)
{
	if (IS_LEAF(tn))
		free_leaf((struct leaf *) tn);
	else
		call_rcu(&tn->rcu, __tnode_free_rcu);
}

static void tnode_free_safe(struct tnode *tn)
{
	BUG_ON(IS_LEAF(tn));
	tn->tnode_free = tnode_free_head;
	tnode_free_head = tn;
	tnode_free_size += sizeof(struct tnode) +
			   (sizeof(struct node *) << tn->bits);
}

static void tnode_free_flush(void)
{
	struct tnode *tn;

	while ((tn = tnode_free_head)) {
		tnode_free_head = tn->tnode_free;
		tn->tnode_free = NULL;
		tnode_free(tn);
	}

	if (tnode_free_size >= PAGE_SIZE * sync_pages) {
		tnode_free_size = 0;
		synchronize_rcu();
	}
}

static struct leaf *leaf_new(void)
{
	struct leaf *l = kmem_cache_alloc(trie_leaf_kmem, GFP_KERNEL);
	if (l) {
		l->parent = T_LEAF;
		INIT_HLIST_HEAD(&l->list);
	}
	return l;
}

static struct leaf_info *leaf_info_new(int plen)
{
	struct leaf_info *li = kmalloc(sizeof(struct leaf_info),  GFP_KERNEL);
	if (li) {
		li->plen = plen;
		INIT_LIST_HEAD(&li->datalh);
	}
	return li;
}

static struct tnode *tnode_new(t_key key, int pos, int bits)
{
	size_t sz = sizeof(struct tnode) + (sizeof(struct node *) << bits);
	struct tnode *tn = tnode_alloc(sz);

	if (tn) {
		tn->parent = T_TNODE;
		tn->pos = pos;
		tn->bits = bits;
		tn->key = key;
		tn->full_children = 0;
		tn->empty_children = 1<<bits;
	}

	pr_debug("AT %p s=%u %lu\n", tn, (unsigned int) sizeof(struct tnode),
		 (unsigned long) (sizeof(struct node) << bits));
	return tn;
}

/*
 * Check whether a tnode 'n' is "full", i.e. it is an internal node
 * and no bits are skipped. See discussion in dyntree paper p. 6
 */

static inline int tnode_full(const struct tnode *tn, const struct node *n)
{
	if (n == NULL || IS_LEAF(n))
		return 0;

	return ((struct tnode *) n)->pos == tn->pos + tn->bits;
}

static inline void put_child(struct trie *t, struct tnode *tn, int i,
			     struct node *n)
{
	tnode_put_child_reorg(tn, i, n, -1);
}

 /*
  * Add a child at position i overwriting the old value.
  * Update the value of full_children and empty_children.
  */

static void tnode_put_child_reorg(struct tnode *tn, int i, struct node *n,
				  int wasfull)
{
	struct node *chi = tn->child[i];
	int isfull;

	BUG_ON(i >= 1<<tn->bits);

	/* update emptyChildren */
	if (n == NULL && chi != NULL)
		tn->empty_children++;
	else if (n != NULL && chi == NULL)
		tn->empty_children--;

	/* update fullChildren */
	if (wasfull == -1)
		wasfull = tnode_full(tn, chi);

	isfull = tnode_full(tn, n);
	if (wasfull && !isfull)
		tn->full_children--;
	else if (!wasfull && isfull)
		tn->full_children++;

	if (n)
		node_set_parent(n, tn);

	rcu_assign_pointer(tn->child[i], n);
}

#define MAX_WORK 10
static struct node *resize(struct trie *t, struct tnode *tn)
{
	int i;
	struct tnode *old_tn;
	int inflate_threshold_use;
	int halve_threshold_use;
	int max_work;

	if (!tn)
		return NULL;

	pr_debug("In tnode_resize %p inflate_threshold=%d threshold=%d\n",
		 tn, inflate_threshold, halve_threshold);

	/* No children */
	if (tn->empty_children == tnode_child_length(tn)) {
		tnode_free_safe(tn);
		return NULL;
	}
	/* One child */
	if (tn->empty_children == tnode_child_length(tn) - 1)
		goto one_child;
	/*
	 * Double as long as the resulting node has a number of
	 * nonempty nodes that are above the threshold.
	 */

	/*
	 * From "Implementing a dynamic compressed trie" by Stefan Nilsson of
	 * the Helsinki University of Technology and Matti Tikkanen of Nokia
	 * Telecommunications, page 6:
	 * "A node is doubled if the ratio of non-empty children to all
	 * children in the *doubled* node is at least 'high'."
	 *
	 * 'high' in this instance is the variable 'inflate_threshold'. It
	 * is expressed as a percentage, so we multiply it with
	 * tnode_child_length() and instead of multiplying by 2 (since the
	 * child array will be doubled by inflate()) and multiplying
	 * the left-hand side by 100 (to handle the percentage thing) we
	 * multiply the left-hand side by 50.
	 *
	 * The left-hand side may look a bit weird: tnode_child_length(tn)
	 * - tn->empty_children is of course the number of non-null children
	 * in the current node. tn->full_children is the number of "full"
	 * children, that is non-null tnodes with a skip value of 0.
	 * All of those will be doubled in the resulting inflated tnode, so
	 * we just count them one extra time here.
	 *
	 * A clearer way to write this would be:
	 *
	 * to_be_doubled = tn->full_children;
	 * not_to_be_doubled = tnode_child_length(tn) - tn->empty_children -
	 *     tn->full_children;
	 *
	 * new_child_length = tnode_child_length(tn) * 2;
	 *
	 * new_fill_factor = 100 * (not_to_be_doubled + 2*to_be_doubled) /
	 *      new_child_length;
	 * if (new_fill_factor >= inflate_threshold)
	 *
	 * ...and so on, tho it would mess up the while () loop.
	 *
	 * anyway,
	 * 100 * (not_to_be_doubled + 2*to_be_doubled) / new_child_length >=
	 *      inflate_threshold
	 *
	 * avoid a division:
	 * 100 * (not_to_be_doubled + 2*to_be_doubled) >=
	 *      inflate_threshold * new_child_length
	 *
	 * expand not_to_be_doubled and to_be_doubled, and shorten:
	 * 100 * (tnode_child_length(tn) - tn->empty_children +
	 *    tn->full_children) >= inflate_threshold * new_child_length
	 *
	 * expand new_child_length:
	 * 100 * (tnode_child_length(tn) - tn->empty_children +
	 *    tn->full_children) >=
	 *      inflate_threshold * tnode_child_length(tn) * 2
	 *
	 * shorten again:
	 * 50 * (tn->full_children + tnode_child_length(tn) -
	 *    tn->empty_children) >= inflate_threshold *
	 *    tnode_child_length(tn)
	 *
	 */

	check_tnode(tn);

	/* Keep root node larger  */

	if (!node_parent((struct node*) tn)) {
		inflate_threshold_use = inflate_threshold_root;
		halve_threshold_use = halve_threshold_root;
	}
	else {
		inflate_threshold_use = inflate_threshold;
		halve_threshold_use = halve_threshold;
	}

	max_work = MAX_WORK;
	while ((tn->full_children > 0 &&  max_work-- &&
		50 * (tn->full_children + tnode_child_length(tn)
		      - tn->empty_children)
		>= inflate_threshold_use * tnode_child_length(tn))) {

		old_tn = tn;
		tn = inflate(t, tn);

		if (IS_ERR(tn)) {
			tn = old_tn;
			break;
		}
	}

	check_tnode(tn);

	/* Return if at least one inflate is run */
	if( max_work != MAX_WORK)
		return (struct node *) tn;

	/*
	 * Halve as long as the number of empty children in this
	 * node is above threshold.
	 */

	max_work = MAX_WORK;
	while (tn->bits > 1 &&  max_work-- &&
	       100 * (tnode_child_length(tn) - tn->empty_children) <
	       halve_threshold_use * tnode_child_length(tn)) {

		old_tn = tn;
		tn = halve(t, tn);
		if (IS_ERR(tn)) {
			tn = old_tn;
			break;
		}
	}


	/* Only one child remains */
	if (tn->empty_children == tnode_child_length(tn) - 1) {
one_child:
		for (i = 0; i < tnode_child_length(tn); i++) {
			struct node *n;

			n = tn->child[i];
			if (!n)
				continue;

			/* compress one level */

			node_set_parent(n, NULL);
			tnode_free_safe(tn);
			return n;
		}
	}
	return (struct node *) tn;
}

static struct tnode *inflate(struct trie *t, struct tnode *tn)
{
	struct tnode *oldtnode = tn;
	int olen = tnode_child_length(tn);
	int i;

	pr_debug("In inflate\n");

	tn = tnode_new(oldtnode->key, oldtnode->pos, oldtnode->bits + 1);

	if (!tn)
		return ERR_PTR(-ENOMEM);

	/*
	 * Preallocate and store tnodes before the actual work so we
	 * don't get into an inconsistent state if memory allocation
	 * fails. In case of failure we return the oldnode and  inflate
	 * of tnode is ignored.
	 */

	for (i = 0; i < olen; i++) {
		struct tnode *inode;

		inode = (struct tnode *) tnode_get_child(oldtnode, i);
		if (inode &&
		    IS_TNODE(inode) &&
		    inode->pos == oldtnode->pos + oldtnode->bits &&
		    inode->bits > 1) {
			struct tnode *left, *right;
			t_key m = ~0U << (KEYLENGTH - 1) >> inode->pos;

			left = tnode_new(inode->key&(~m), inode->pos + 1,
					 inode->bits - 1);
			if (!left)
				goto nomem;

			right = tnode_new(inode->key|m, inode->pos + 1,
					  inode->bits - 1);

			if (!right) {
				tnode_free(left);
				goto nomem;
			}

			put_child(t, tn, 2*i, (struct node *) left);
			put_child(t, tn, 2*i+1, (struct node *) right);
		}
	}

	for (i = 0; i < olen; i++) {
		struct tnode *inode;
		struct node *node = tnode_get_child(oldtnode, i);
		struct tnode *left, *right;
		int size, j;

		/* An empty child */
		if (node == NULL)
			continue;

		/* A leaf or an internal node with skipped bits */

		if (IS_LEAF(node) || ((struct tnode *) node)->pos >
		   tn->pos + tn->bits - 1) {
			if (tkey_extract_bits(node->key,
					      oldtnode->pos + oldtnode->bits,
					      1) == 0)
				put_child(t, tn, 2*i, node);
			else
				put_child(t, tn, 2*i+1, node);
			continue;
		}

		/* An internal node with two children */
		inode = (struct tnode *) node;

		if (inode->bits == 1) {
			put_child(t, tn, 2*i, inode->child[0]);
			put_child(t, tn, 2*i+1, inode->child[1]);

			tnode_free_safe(inode);
			continue;
		}

		/* An internal node with more than two children */

		/* We will replace this node 'inode' with two new
		 * ones, 'left' and 'right', each with half of the
		 * original children. The two new nodes will have
		 * a position one bit further down the key and this
		 * means that the "significant" part of their keys
		 * (see the discussion near the top of this file)
		 * will differ by one bit, which will be "0" in
		 * left's key and "1" in right's key. Since we are
		 * moving the key position by one step, the bit that
		 * we are moving away from - the bit at position
		 * (inode->pos) - is the one that will differ between
		 * left and right. So... we synthesize that bit in the
		 * two  new keys.
		 * The mask 'm' below will be a single "one" bit at
		 * the position (inode->pos)
		 */

		/* Use the old key, but set the new significant
		 *   bit to zero.
		 */

		left = (struct tnode *) tnode_get_child(tn, 2*i);
		put_child(t, tn, 2*i, NULL);

		BUG_ON(!left);

		right = (struct tnode *) tnode_get_child(tn, 2*i+1);
		put_child(t, tn, 2*i+1, NULL);

		BUG_ON(!right);

		size = tnode_child_length(left);
		for (j = 0; j < size; j++) {
			put_child(t, left, j, inode->child[j]);
			put_child(t, right, j, inode->child[j + size]);
		}
		put_child(t, tn, 2*i, resize(t, left));
		put_child(t, tn, 2*i+1, resize(t, right));

		tnode_free_safe(inode);
	}
	tnode_free_safe(oldtnode);
	return tn;
nomem:
	{
		int size = tnode_child_length(tn);
		int j;

		for (j = 0; j < size; j++)
			if (tn->child[j])
				tnode_free((struct tnode *)tn->child[j]);

		tnode_free(tn);

		return ERR_PTR(-ENOMEM);
	}
}

static struct tnode *halve(struct trie *t, struct tnode *tn)
{
	struct tnode *oldtnode = tn;
	struct node *left, *right;
	int i;
	int olen = tnode_child_length(tn);

	pr_debug("In halve\n");

	tn = tnode_new(oldtnode->key, oldtnode->pos, oldtnode->bits - 1);

	if (!tn)
		return ERR_PTR(-ENOMEM);

	/*
	 * Preallocate and store tnodes before the actual work so we
	 * don't get into an inconsistent state if memory allocation
	 * fails. In case of failure we return the oldnode and halve
	 * of tnode is ignored.
	 */

	for (i = 0; i < olen; i += 2) {
		left = tnode_get_child(oldtnode, i);
		right = tnode_get_child(oldtnode, i+1);

		/* Two nonempty children */
		if (left && right) {
			struct tnode *newn;

			newn = tnode_new(left->key, tn->pos + tn->bits, 1);

			if (!newn)
				goto nomem;

			put_child(t, tn, i/2, (struct node *)newn);
		}

	}

	for (i = 0; i < olen; i += 2) {
		struct tnode *newBinNode;

		left = tnode_get_child(oldtnode, i);
		right = tnode_get_child(oldtnode, i+1);

		/* At least one of the children is empty */
		if (left == NULL) {
			if (right == NULL)    /* Both are empty */
				continue;
			put_child(t, tn, i/2, right);
			continue;
		}

		if (right == NULL) {
			put_child(t, tn, i/2, left);
			continue;
		}

		/* Two nonempty children */
		newBinNode = (struct tnode *) tnode_get_child(tn, i/2);
		put_child(t, tn, i/2, NULL);
		put_child(t, newBinNode, 0, left);
		put_child(t, newBinNode, 1, right);
		put_child(t, tn, i/2, resize(t, newBinNode));
	}
	tnode_free_safe(oldtnode);
	return tn;
nomem:
	{
		int size = tnode_child_length(tn);
		int j;

		for (j = 0; j < size; j++)
			if (tn->child[j])
				tnode_free((struct tnode *)tn->child[j]);

		tnode_free(tn);

		return ERR_PTR(-ENOMEM);
	}
}

/* readside must use rcu_read_lock currently dump routines
 via get_fa_head and dump */

static struct leaf_info *find_leaf_info(struct leaf *l, int plen)
{
	struct hlist_head *head = &l->list;
	struct hlist_node *node;
	struct leaf_info *li;

	hlist_for_each_entry_rcu(li, node, head, hlist)
		if (li->plen == plen)
			return li;

	return NULL;
}

static inline struct list_head *get_fa_head(struct leaf *l, int plen)
{
	struct leaf_info *li = find_leaf_info(l, plen);

	if (!li)
		return NULL;

	return &li->datalh;
}

static void insert_leaf_info(struct hlist_head *head, struct leaf_info *new)
{
	struct leaf_info *li = NULL, *last = NULL;
	struct hlist_node *node;

	if (hlist_empty(head)) {
		hlist_add_head_rcu(&new->hlist, head);
	} else {
		hlist_for_each_entry(li, node, head, hlist) {
			if (new->plen > li->plen)
				break;

			last = li;
		}
		if (last)
			hlist_add_after_rcu(&last->hlist, &new->hlist);
		else
			hlist_add_before_rcu(&new->hlist, &li->hlist);
	}
}

/* rcu_read_lock needs to be hold by caller from readside */

static struct leaf *
trie_find_node(struct trie *t, u32 key)
{
	int pos;
	struct tnode *tn;
	struct node *n;

	pos = 0;
	n = rcu_dereference_check(t->trie,
				  rcu_read_lock_held() ||
				  lockdep_rtnl_is_held());

	printk(KERN_INFO "%s trie: %p\n", __func__, n);
	while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
		tn = (struct tnode *) n;

		check_tnode(tn);

		if (tkey_sub_equals(tn->key, pos, tn->pos-pos, key)) {
			pos = tn->pos + tn->bits;
			n = tnode_get_child_rcu(tn,
						tkey_extract_bits(key,
								  tn->pos,
								  tn->bits));
		} else
			break;
	}
	/* Case we have found a leaf. Compare prefixes */

	if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key))
		return (struct leaf *)n;

	return NULL;
}

static void trie_rebalance(struct trie *t, struct tnode *tn)
{
	int wasfull;
	t_key cindex, key;
	struct tnode *tp;

	key = tn->key;

	while (tn != NULL && (tp = node_parent((struct node *)tn)) != NULL) {
		cindex = tkey_extract_bits(key, tp->pos, tp->bits);
		wasfull = tnode_full(tp, tnode_get_child(tp, cindex));
		tn = (struct tnode *) resize(t, (struct tnode *)tn);

		tnode_put_child_reorg((struct tnode *)tp, cindex,
				      (struct node *)tn, wasfull);

		tp = node_parent((struct node *) tn);
		if (!tp)
			rcu_assign_pointer(t->trie, (struct node *)tn);

		tnode_free_flush();
		if (!tp)
			break;
		tn = tp;
	}

	/* Handle last (top) tnode */
	if (IS_TNODE(tn))
		tn = (struct tnode *)resize(t, (struct tnode *)tn);

	rcu_assign_pointer(t->trie, (struct node *)tn);
	tnode_free_flush();
}

/* only used from updater-side */

static struct list_head *trie_insert_node(struct trie *t, u32 key, int plen)
{
	int pos, newpos;
	struct tnode *tp = NULL, *tn = NULL;
	struct node *n;
	struct leaf *l;
	int missbit;
	struct list_head *fa_head = NULL;
	struct leaf_info *li;
	t_key cindex;

	pos = 0;
	n = t->trie;

	/* If we point to NULL, stop. Either the tree is empty and we should
	 * just put a new leaf in if, or we have reached an empty child slot,
	 * and we should just put our new leaf in that.
	 * If we point to a T_TNODE, check if it matches our key. Note that
	 * a T_TNODE might be skipping any number of bits - its 'pos' need
	 * not be the parent's 'pos'+'bits'!
	 *
	 * If it does match the current key, get pos/bits from it, extract
	 * the index from our key, push the T_TNODE and walk the tree.
	 *
	 * If it doesn't, we have to replace it with a new T_TNODE.
	 *
	 * If we point to a T_LEAF, it might or might not have the same key
	 * as we do. If it does, just change the value, update the T_LEAF's
	 * value, and return it.
	 * If it doesn't, we need to replace it with a T_TNODE.
	 */

	while (n != NULL &&  NODE_TYPE(n) == T_TNODE) {
		tn = (struct tnode *) n;

		check_tnode(tn);

		if (tkey_sub_equals(tn->key, pos, tn->pos-pos, key)) {
			tp = tn;
			pos = tn->pos + tn->bits;
			n = tnode_get_child(tn,
					    tkey_extract_bits(key,
							      tn->pos,
							      tn->bits));

			BUG_ON(n && node_parent(n) != tn);
		} else
			break;
	}

	/*
	 * n  ----> NULL, LEAF or TNODE
	 *
	 * tp is n's (parent) ----> NULL or TNODE
	 */

	BUG_ON(tp && IS_LEAF(tp));

	/* Case 1: n is a leaf. Compare prefixes */

	if (n != NULL && IS_LEAF(n) && tkey_equals(key, n->key)) {
		l = (struct leaf *) n;
		li = leaf_info_new(plen);

		if (!li)
			return NULL;

		fa_head = &li->datalh;
		insert_leaf_info(&l->list, li);
		goto done;
	}
	l = leaf_new();

	if (!l)
		return NULL;

	l->key = key;
	li = leaf_info_new(plen);

	if (!li) {
		free_leaf(l);
		return NULL;
	}

	fa_head = &li->datalh;
	insert_leaf_info(&l->list, li);

	if (t->trie && n == NULL) {
		/* Case 2: n is NULL, and will just insert a new leaf */

		node_set_parent((struct node *)l, tp);

		cindex = tkey_extract_bits(key, tp->pos, tp->bits);
		put_child(t, (struct tnode *)tp, cindex, (struct node *)l);
	} else {
		/* Case 3: n is a LEAF or a TNODE and the key doesn't match. */
		/*
		 *  Add a new tnode here
		 *  first tnode need some special handling
		 */

		if (tp)
			pos = tp->pos+tp->bits;
		else
			pos = 0;

		if (n) {
			newpos = tkey_mismatch(key, pos, n->key);
			tn = tnode_new(n->key, newpos, 1);
		} else {
			newpos = 0;
			tn = tnode_new(key, newpos, 1); /* First tnode */
		}

		if (!tn) {
			free_leaf_info(li);
			free_leaf(l);
			return NULL;
		}

		node_set_parent((struct node *)tn, tp);

		missbit = tkey_extract_bits(key, newpos, 1);
		put_child(t, tn, missbit, (struct node *)l);
		put_child(t, tn, 1-missbit, n);

		if (tp) {
			cindex = tkey_extract_bits(key, tp->pos, tp->bits);
			put_child(t, (struct tnode *)tp, cindex,
				  (struct node *)tn);
		} else {
			rcu_assign_pointer(t->trie, (struct node *)tn);
			tp = tn;
		}
	}

	if (tp && tp->pos + tp->bits > 32)
		pr_warning("map_trie"
			   " tp=%p pos=%d, bits=%d, key=%0x plen=%d\n",
			   tp, tp->pos, tp->bits, key, plen);

	/* Rebalance the trie */

	trie_rebalance(t, tp);
done:
	return fa_head;
}


/* should be called with rcu_read_lock */
static int check_leaf(struct trie *t, struct leaf *l,
		      t_key key,  const struct flowi *flp,
		      struct map_result *res)
{
	struct leaf_info *li;
	struct hlist_head *hhead = &l->list;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(li, node, hhead, hlist) {
		int err;
		int plen = li->plen;
		__be32 mask = inet_make_mask(plen);

		if (l->key != (key & ntohl(mask)))
			continue;

		err = map_semantic_match(&li->datalh, flp, res, plen);

		if (err <= 0)
			return err;
	}

	return 1;
}

/*
 * Remove the leaf and return parent.
 */
static void trie_leaf_remove(struct trie *t, struct leaf *l)
{
	struct tnode *tp = node_parent((struct node *) l);

	pr_debug("entering trie_leaf_remove(%p)\n", l);

	if (tp) {
		t_key cindex = tkey_extract_bits(l->key, tp->pos, tp->bits);
		put_child(t, (struct tnode *)tp, cindex, NULL);
		trie_rebalance(t, tp);
	} else
		rcu_assign_pointer(t->trie, NULL);

	free_leaf(l);
}

/* head: map_entry list */
static int trie_flush_list(struct list_head *head)
{
	struct map_entry *me, *me_node;
	int found = 0;

	list_for_each_entry_safe(me, me_node, head, list) {
		printk(KERN_INFO "%s map:(%p)\n", __func__, me);
		found += release_map(me);
		list_del_rcu(&me->list);
		map_free_mem_rcu(me);
	}
	return found;
}

static int trie_flush_leaf(struct leaf *l)
{
	int found = 0;
	struct hlist_head *lih = &l->list;
	struct hlist_node *node, *tmp;
	struct leaf_info *li = NULL;

	hlist_for_each_entry_safe(li, node, tmp, lih, hlist) {
		printk(KERN_INFO "%s lilen:%d (%p)\n", __func__, li->plen, li);
		found += trie_flush_list(&li->datalh);

		if (list_empty(&li->datalh)) {
			hlist_del_rcu(&li->hlist);
			free_leaf_info(li);
		}
	}
	return found;
}

/*
 * Scan for the next right leaf starting at node p->child[idx]
 * Since we have back pointer, no recursion necessary.
 */
static struct leaf *leaf_walk_rcu(struct tnode *p, struct node *c)
{
	do {
		t_key idx;

		if (c)
			idx = tkey_extract_bits(c->key, p->pos, p->bits) + 1;
		else
			idx = 0;

		while (idx < 1u << p->bits) {
			c = tnode_get_child_rcu(p, idx++);
			if (!c)
				continue;

			if (IS_LEAF(c)) {
				prefetch(p->child[idx]);
				return (struct leaf *) c;
			}

			/* Rescan start scanning in new node */
			p = (struct tnode *) c;
			idx = 0;
		}

		/* Node empty, walk back up to parent */
		c = (struct node *) p;
	} while ( (p = node_parent_rcu(c)) != NULL);

	return NULL; /* Root of trie */
}

static struct leaf *trie_firstleaf(struct trie *t)
{
	struct tnode *n = (struct tnode *) rcu_dereference(t->trie);

	if (!n)
		return NULL;

	if (IS_LEAF(n))          /* trie is just a leaf */
		return (struct leaf *) n;

	return leaf_walk_rcu(n, NULL);
}

static struct leaf *trie_nextleaf(struct leaf *l)
{
	struct node *c = (struct node *) l;
	struct tnode *p = node_parent_rcu(c);

	if (!p)
		return NULL;	/* trie with just one leaf */

	return leaf_walk_rcu(p, c);
}

static struct leaf *trie_leafindex(struct trie *t, int index)
{
	struct leaf *l = trie_firstleaf(t);

	while (l && index-- > 0)
		l = trie_nextleaf(l);

	return l;
}

/*
 * Caller must hold table lock.
 */
int map_table_flush(struct map_table *tb)
{
	struct trie *t = (struct trie *) tb->tb_data;
	struct leaf *l, *ll = NULL;
	int found = 0;

	for (l = trie_firstleaf(t); l; l = trie_nextleaf(l)) {
		found += trie_flush_leaf(l);

		if (ll && hlist_empty(&ll->list))
			trie_leaf_remove(t, ll);
		ll = l;
	}

	if (ll && hlist_empty(&ll->list))
		trie_leaf_remove(t, ll);

	pr_debug("trie_flush found=%d\n", found);
	return found;
}

static int fn_trie_dump_me(t_key key, int plen, struct list_head *meh,
			   struct map_table *tb, struct genl_family *family,
			   struct sk_buff *skb, struct netlink_callback *cb)
{
	int i, s_i;
	struct map_entry *me;
	__be32 xkey = htonl(key);

	s_i = cb->args[5];
	i = 0;

	/* rcu_read_lock is hold by caller */

	list_for_each_entry_rcu(me, meh, list) {
		if (i < s_i) {
			i++;
			continue;
		}

		if (dump_map(skb, NETLINK_CB(cb->skb).pid,
			     cb->nlh->nlmsg_seq,
			     family,
			     xkey,
			     plen,
			     &me->rlocs,
			     me->flags,
			     NLM_F_MULTI) < 0) {
			cb->args[5] = i;
			return -1;
		}
		i++;
	}
	cb->args[5] = i;
	return skb->len;
}


static int fn_trie_dump_leaf(struct leaf *l, struct map_table *tb,
			     struct genl_family *family,
			     struct sk_buff *skb, struct netlink_callback *cb)
{
	struct leaf_info *li;
	struct hlist_node *node;
	int i, s_i;

	s_i = cb->args[4];
	i = 0;

	/* rcu_read_lock is hold by caller */
	hlist_for_each_entry_rcu(li, node, &l->list, hlist) {
		if (i < s_i) {
			i++;
			continue;
		}

		if (i > s_i)
			cb->args[5] = 0;

		if (list_empty(&li->datalh))
			continue;

		if (fn_trie_dump_me(l->key, li->plen, &li->datalh, tb,
				    family, skb, cb) < 0) {
			cb->args[4] = i;
			return -1;
		}
		i++;
	}

	cb->args[4] = i;
	return skb->len;
}

int map_table_dump(struct map_table *tb, struct genl_family *family,
		   struct sk_buff *skb,
		   struct netlink_callback *cb)
{
	struct leaf *l;
	struct trie *t = (struct trie *) tb->tb_data;
	t_key key = cb->args[2];
	int count = cb->args[3];

	rcu_read_lock();
	/* Dump starting at last key.
	 * Note: 0.0.0.0/0 (ie default) is first key.
	 */
	if (count == 0)
		l = trie_firstleaf(t);
	else {
		/* Normally, continue from last key, but if that is missing
		 * fallback to using slow rescan
		 */
		l = trie_find_node(t, key);
		if (!l)
			l = trie_leafindex(t, count);
	}

	while (l) {
		cb->args[2] = l->key;
		if (fn_trie_dump_leaf(l, tb, family, skb, cb) < 0) {
			cb->args[3] = count;
			rcu_read_unlock();
			return -1;
		}

		++count;
		l = trie_nextleaf(l);
		memset(&cb->args[4], 0,
		       sizeof(cb->args) - 4*sizeof(cb->args[0]));
	}
	cb->args[3] = count;
	rcu_read_unlock();

	return skb->len;
}

int map_table_insert(struct map_table *tb, struct map_config *cfg)
{
	struct trie *t = (struct trie *) tb->tb_data;
	int plen = cfg->mc_dst_len;
	u32 key, mask;
	int err;
	struct leaf *l;
	struct map_entry *me, *new_me;
	struct list_head *me_head = NULL;

	if (plen > 32)
		return -EINVAL;

	key = ntohl(cfg->mc_dst);

	pr_debug("Insert table %08x/%d\n", key, plen);
	printk(KERN_INFO "%s %08x/%d\n", __func__, key, plen);

	mask = ntohl(inet_make_mask(plen));

	if (key & ~mask)
		return -EINVAL;

	key = key & mask;

	l = trie_find_node(t, key);
	me = NULL;

	if (l) {
		me_head = get_fa_head(l, plen);
		me = map_find(me_head);
	}

	if (me) {
		/* just one map per prefix for now */
		err = -EEXIST;
		goto err;
	} else {
		err = -ENOBUFS;
		new_me = kmem_cache_alloc(map_entry_kmem, GFP_KERNEL);
		if (new_me == NULL)
			goto err;

		new_me->flags = cfg->mc_map_flags;
		INIT_LIST_HEAD(&new_me->rlocs);
		INIT_RCU_HEAD(&new_me->rcu);
		list_add_rcu(&cfg->mc_rloc->list, &new_me->rlocs);

		atomic_set(&new_me->rloc_cnt, cfg->mc_rloc_cnt);

		me_head = trie_insert_node(t, key, plen);
		if (unlikely(!me_head)) {
			err = -ENOMEM;
			goto out_free_new_me;
		}

		list_add_rcu(&new_me->list, me_head);

		printk(KERN_INFO "%s maphead:%p newmaplist:%p\n", __func__, me_head, &new_me->list);
	}

	return 0;
out_free_new_me:
	kmem_cache_free(map_entry_kmem, new_me);
err:
	return err;
}

int map_table_lookup(struct map_table *tb, const struct flowi *flp,
		     struct map_result *res)
{
	struct trie *t = (struct trie *) tb->tb_data;
	int ret;
	struct node *n;
	struct tnode *pn;
	int pos, bits;
	t_key key = ntohl(flp->fl4_dst);
	int chopped_off;
	t_key cindex = 0;
	int current_prefix_length = KEYLENGTH;
	struct tnode *cn;
	t_key node_prefix, key_prefix, pref_mismatch;
	int mp;

	rcu_read_lock();

	n = rcu_dereference(t->trie);
	if (!n)
		goto failed;

	/* Just a leaf? */
	if (IS_LEAF(n)) {
		ret = check_leaf(t, (struct leaf *)n, key, flp, res);
		printk(KERN_INFO "%s just a leaf %d\n", __func__, ret);
		goto found;
	}

	pn = (struct tnode *) n;
	chopped_off = 0;

	while (pn) {
		pos = pn->pos;
		bits = pn->bits;

		if (!chopped_off)
			cindex = tkey_extract_bits(mask_pfx(key, current_prefix_length),
						   pos, bits);

		n = tnode_get_child_rcu(pn, cindex);

		if (n == NULL) {
			goto backtrace;
		}

		if (IS_LEAF(n)) {
			ret = check_leaf(t, (struct leaf *)n, key, flp, res);
			if (ret > 0)
				goto backtrace;
			printk(KERN_INFO "%s mark2 normal %d\n", __func__, ret);
			goto found;
		}

		cn = (struct tnode *)n;

		/*
		 * It's a tnode, and we can do some extra checks here if we
		 * like, to avoid descending into a dead-end branch.
		 * This tnode is in the parent's child array at index
		 * key[p_pos..p_pos+p_bits] but potentially with some bits
		 * chopped off, so in reality the index may be just a
		 * subprefix, padded with zero at the end.
		 * We can also take a look at any skipped bits in this
		 * tnode - everything up to p_pos is supposed to be ok,
		 * and the non-chopped bits of the index (se previous
		 * paragraph) are also guaranteed ok, but the rest is
		 * considered unknown.
		 *
		 * The skipped bits are key[pos+bits..cn->pos].
		 */

		/* If current_prefix_length < pos+bits, we are already doing
		 * actual prefix  matching, which means everything from
		 * pos+(bits-chopped_off) onward must be zero along some
		 * branch of this subtree - otherwise there is *no* valid
		 * prefix present. Here we can only check the skipped
		 * bits. Remember, since we have already indexed into the
		 * parent's child array, we know that the bits we chopped of
		 * *are* zero.
		 */

		/* NOTA BENE: Checking only skipped bits
		   for the new node here */

		if (current_prefix_length < pos+bits) {
			if (tkey_extract_bits(cn->key, current_prefix_length,
						cn->pos - current_prefix_length)
			    || !(cn->child[0]))
				goto backtrace;
		}

		/*
		 * If chopped_off=0, the index is fully validated and we
		 * only need to look at the skipped bits for this, the new,
		 * tnode. What we actually want to do is to find out if
		 * these skipped bits match our key perfectly, or if we will
		 * have to count on finding a matching prefix further down,
		 * because if we do, we would like to have some way of
		 * verifying the existence of such a prefix at this point.
		 */

		/* The only thing we can do at this point is to verify that
		 * any such matching prefix can indeed be a prefix to our
		 * key, and if the bits in the node we are inspecting that
		 * do not match our key are not ZERO, this cannot be true.
		 * Thus, find out where there is a mismatch (before cn->pos)
		 * and verify that all the mismatching bits are zero in the
		 * new tnode's key.
		 */

		/*
		 * Note: We aren't very concerned about the piece of
		 * the key that precede pn->pos+pn->bits, since these
		 * have already been checked. The bits after cn->pos
		 * aren't checked since these are by definition
		 * "unknown" at this point. Thus, what we want to see
		 * is if we are about to enter the "prefix matching"
		 * state, and in that case verify that the skipped
		 * bits that will prevail throughout this subtree are
		 * zero, as they have to be if we are to find a
		 * matching prefix.
		 */

		node_prefix = mask_pfx(cn->key, cn->pos);
		key_prefix = mask_pfx(key, cn->pos);
		pref_mismatch = key_prefix^node_prefix;
		mp = 0;

		/*
		 * In short: If skipped bits in this node do not match
		 * the search key, enter the "prefix matching"
		 * state.directly.
		 */
		if (pref_mismatch) {
			while (!(pref_mismatch & (1<<(KEYLENGTH-1)))) {
				mp++;
				pref_mismatch = pref_mismatch << 1;
			}
			key_prefix = tkey_extract_bits(cn->key, mp, cn->pos-mp);

			if (key_prefix != 0)
				goto backtrace;

			if (current_prefix_length >= cn->pos)
				current_prefix_length = mp;
		}

		pn = (struct tnode *)n; /* Descend */
		chopped_off = 0;
		continue;

backtrace:
		chopped_off++;

		/* As zero don't change the child key (cindex) */
		while ((chopped_off <= pn->bits)
		       && !(cindex & (1<<(chopped_off-1))))
			chopped_off++;

		/* Decrease current_... with bits chopped off */
		if (current_prefix_length > pn->pos + pn->bits - chopped_off)
			current_prefix_length = pn->pos + pn->bits
				- chopped_off;

		/*
		 * Either we do the actual chop off according or if we have
		 * chopped off all bits in this tnode walk up to our parent.
		 */

		if (chopped_off <= pn->bits) {
			cindex &= ~(1 << (chopped_off-1));
		} else {
			struct tnode *parent = node_parent_rcu((struct node *) pn);
			if (!parent)
				goto failed;

			/* Get Child's index */
			cindex = tkey_extract_bits(pn->key, parent->pos, parent->bits);
			pn = parent;
			chopped_off = 0;

			goto backtrace;
		}
	}
failed:
	ret = 1;
found:
	rcu_read_unlock();
	return ret;
}

void map_hash_init(void)
{
	map_entry_kmem = kmem_cache_create("ip_map_entry",
					  sizeof(struct map_entry),
					  0, SLAB_PANIC, NULL);

	trie_leaf_kmem = kmem_cache_create("ip_map_trie",
					   max(sizeof(struct leaf),
					       sizeof(struct leaf_info)),
					   0, SLAB_PANIC, NULL);
}


/* Fix more generic FIB names for init later */
struct map_table *map_hash_table(void)
{
	struct map_table *tb;
	struct trie *t;

	tb = kmalloc(sizeof(struct map_table) + sizeof(struct trie),
		     GFP_KERNEL);
	if (tb == NULL)
		return NULL;

	t = (struct trie *) tb->tb_data;
	memset(t, 0, sizeof(*t));

	return tb;
}
