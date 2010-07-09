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
