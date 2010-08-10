/*
 *	Linux LISP: Locator/ID Separation Protocol
 *
 *	Definitions for the LISP protocol.
 *
 *	Author: Alex Lorca <alex.lorca@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#ifndef _LINUX_LISP_H_
#define _LINUX_LISP_H_

#include <linux/types.h>
#include <asm/byteorder.h>

#define LISP_DATA_PORT 4341

struct lisphdr {
	union {
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			__u32	reserved:3,
				iid_present:1,
				map_ver:1,
				echo_nonce:1,
				lsb_enable:1,
				nonce_present:1,
				nonce:24;
		};
		struct {
			__u32	reserved:3,
				iid_present:1,
				map_ver:1,
				echo_nonce:1,
				lsb_enable:1,
				nonce_present:1,
				dmapver:12,
				smapver:12;
#elif defined(__BIG_ENDIAN_BITFIELD)
			__u32	nonce_present:1,
				lsb_enable:1,
				echo_nonce:1,
				map_ver:1,
				iid_present:1,
				reserved:3,
				nonce:24;
		};
		struct {
			__u32	nonce_present:1,
				lsb_enable:1,
				echo_nonce:1,
				map_ver:1,
				iid_present:1,
				reserved:3,
				smapver:12,
				dmapver:12;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
	union {
		__be32	lsb;
		struct {
			__u32	instance_id:24,
				lsb:8;
		};
	};
};

/* Netlink definitions */

#define LISP_GNL_NAME "LISP"
#define LISP_GNL_VERSION 1

/* Attributes */
enum {
	LISP_GNL_ATTR_UNSPEC,
	LISP_GNL_ATTR_MAP,
	LISP_GNL_ATTR_MAPF,
	__LISP_GNL_ATTR_MAX,
};
#define LISP_GNL_ATTR_MAX (__LISP_GNL_ATTR_MAX - 1)

enum {
	LISP_GNL_ATTR_MAP_UNSPEC,
	LISP_GNL_ATTR_MAP_EID,
	LISP_GNL_ATTR_MAP_EIDLEN,
	LISP_GNL_ATTR_MAP_RLOC,
	LISP_GNL_ATTR_MAP_WEIGHT,
	LISP_GNL_ATTR_MAP_PRIO,
	__LISP_GNL_ATTR_MAP_MAX,
};
#define LISP_GNL_ATTR_MAP_MAX (__LISP_GNL_ATTR_MAP_MAX - 1)

/* Attribute policy */
static struct nla_policy lisp_gnl_policy[LISP_GNL_ATTR_MAX + 1] = {
	[LISP_GNL_ATTR_MAP]	= { .type = NLA_NESTED },
	[LISP_GNL_ATTR_MAPF]	= { .type = NLA_U8 },
};

static struct nla_policy lisp_gnl_map_policy[LISP_GNL_ATTR_MAP_MAX + 1] = {
	[LISP_GNL_ATTR_MAP_EID]		= { .type = NLA_U32 },
	[LISP_GNL_ATTR_MAP_EIDLEN]	= { .type = NLA_U8 },
	[LISP_GNL_ATTR_MAP_RLOC]	= { .type = NLA_U32 },
	[LISP_GNL_ATTR_MAP_WEIGHT]	= { .type = NLA_U8 },
	[LISP_GNL_ATTR_MAP_PRIO]	= { .type = NLA_U8 },
};

/* Commands */
enum {
	LISP_GNL_CMD_UNSPEC,
	LISP_GNL_CMD_ADDMAP,
	LISP_GNL_CMD_SHOWMAP,
	__LISP_GNL_CMD_MAX,
};
#define LISP_GNL_CMD_MAX (__LISP_GNL_CMD_MAX - 1)

/* Map Flags */
#define LISP_MAP_F_UP		1	/* Mapping usable */
#define LISP_MAP_F_LOCAL	2	/* Mapping part of LISP Databse */
#define LISP_MAP_F_STATIC	4	/* Mapping added manually */

/* RLOC Flags */
#define LISP_RLOC_F_REACH	1	/* RLOC rechable */


#ifdef __KERNEL__
#include <linux/skbuff.h>
#include <net/udp.h>

static inline struct lisphdr *lisp_hdr(const struct sk_buff *skb)
{
	return (struct lisphdr *)
		(skb_transport_header(skb) + sizeof(struct udphdr));
}

#endif

#endif	/* _LINUX_LISP_H_ */
