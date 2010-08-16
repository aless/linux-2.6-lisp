/*
 *	Linux LISP:	Locator/ID Separation Protocol
 *
 *	Author: Alex Lorca <alex.lorca@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <net/netns/generic.h>
#include <linux/device.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp_states.h>
#include <net/inet_hashtables.h>
#include <linux/lisp.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/if_tunnel.h>
#include <net/ipip.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/inetdevice.h>
#include <net/inet_ecn.h>

#include "lisp.h"
#include "map_trie.h"

static void lisp_dev_setup(struct net_device *dev);


static int lisp_net_id __read_mostly;

static struct lisp_tunnel *lisp_tunnel_lookup(struct net *net, u32 local)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct net_device *dev;
	struct lisp_tunnel *tun;
	unsigned h = HASH(local);

	list_for_each_entry_rcu(tun, &(lin->tunnels[h]),  list) {
		if (tun->parms.iph.saddr == local)
			return tun;
	};

	dev = lin->fb_tunnel_dev;
	tun = (struct lisp_tunnel *)netdev_priv(dev);
	if (tun->parms.iph.saddr == local)
		return tun;

	return NULL;
}

static struct lisp_tunnel *lisp_tunnel_lookup_dst(struct net *net, u32 local)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct net_device *dev;
	struct lisp_tunnel *tun;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		list_for_each_entry_rcu(tun, &(lin->tunnels[i]),  list) {
			if (inet_select_addr(tun->dev, 0, 0) == local)
				return tun;
		};
	}

	if (inet_select_addr(lin->fb_tunnel_dev, 0, 0) == local) {
		dev = lin->fb_tunnel_dev;
		tun = (struct lisp_tunnel *)netdev_priv(dev);
		return tun;
	}

	return NULL;
}

static void __lisp_tunnel_link(struct lisp_net *lin, struct lisp_tunnel *tun)
{
	unsigned h = HASH(tun->parms.iph.saddr);

	list_add_tail_rcu(&tun->list, &lin->tunnels[h]);
}

static void lisp_tunnel_link(struct lisp_net *lin, struct lisp_tunnel *tun)
{
	spin_lock_bh(&lin->lock);
	__lisp_tunnel_link(lin, tun);
	spin_unlock_bh(&lin->lock);
}

static void __lisp_tunnel_unlink(struct lisp_net *lin, struct lisp_tunnel *tun)
{
	list_del_rcu(&tun->list);
}

static void lisp_tunnel_unlink(struct lisp_net *lin, struct lisp_tunnel *tun)
{
	/* TODO: remove local rloc mapings */

	spin_lock_bh(&lin->lock);
	__lisp_tunnel_unlink(lin, tun);
	spin_unlock_bh(&lin->lock);
}

static struct lisp_tunnel *lisp_tunnel_locate(struct net *net,
					      struct ip_tunnel_parm *parms,
					      int create)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct lisp_tunnel *tun;
	u32 local = parms->iph.saddr;
	struct net_device *dev;
	char name[IFNAMSIZ];
	int err;

	tun = lisp_tunnel_lookup(net, local);
	if (tun)
		return tun;
	if (!create)
		return NULL;

	if (parms->name[0])
		strlcpy(name, parms->name, IFNAMSIZ);
	else
		sprintf(name, "lisp%%d");

	dev = alloc_netdev(sizeof(struct lisp_tunnel), name, lisp_dev_setup);
	if (dev == NULL)
		return NULL;

	dev_net_set(dev, net);

	if (strchr(name, '%')) {
		if (dev_alloc_name(dev, name) < 0)
			goto failed_free;
	}

	tun = netdev_priv(dev);
	tun->dev = dev;
	memcpy(&tun->parms, parms, sizeof(*parms));

	err = register_netdevice(dev);
	if (err < 0)
		goto failed_free;

	lisp_tunnel_link(lin, tun);
	return tun;

failed_free:
	free_netdev(dev);
	return NULL;
}

static __be32 lisp_rloc_lookup(struct net *net, struct flowi *fl)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct map_result mr;
	int res;

	res = map_table_lookup(lin->maps, fl, &mr);
	if (res != 1)
		return mr.rloc->rloc;
	else
		return 0;
}

static void lisp_rloc_append(struct map_entry *map, struct rloc_entry *rloc)
{
	struct rloc_entry *re = NULL;
	struct rloc_entry *resp = NULL;

	list_for_each_entry_rcu(re, &map->rlocs, list) {
		if (re->priority >= rloc->priority)
			break;
		resp = re;
	}

	atomic_inc(&map->rloc_cnt);
	if (!resp)
		list_add_rcu(&rloc->list, &map->rlocs);
	else
		list_add_rcu(&rloc->list, &resp->list);
}

void lisp_rloc_free(struct rcu_head *head)
{
	struct rloc_entry *rloc = container_of(head, struct rloc_entry, rcu);
	kfree(rloc);
}

static void lisp_rloc_del(struct rloc_entry *rloc)
{
	list_del_rcu(&rloc->list);
	call_rcu(&rloc->rcu, lisp_rloc_free);
}

void lisp_map_free(struct rcu_head *head)
{
	struct map_entry *map = container_of(head, struct map_entry, rcu);
	kfree(map);
}

static void __lisp_map_del(struct map_entry *map)
{
	struct rloc_entry *rloc, *rtmp;
	int cnt = atomic_read(&map->rloc_cnt);

	if (cnt > 0) {
		list_for_each_entry_safe(rloc, rtmp, &map->rlocs, list)
			lisp_rloc_del(rloc);
	}
	list_del_rcu(&map->list);
	call_rcu(&map->rcu, lisp_map_free);
}

static void lisp_map_del(struct lisp_net *lin, struct map_entry *map)
{
	spin_lock_bh(&lin->lock);
	__lisp_map_del(map);
	spin_unlock_bh(&lin->lock);
}

static int lisp_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr,
		int cmd)
{
	int err = 0;
	struct ip_tunnel_parm parms;
	struct lisp_tunnel *tun;
	struct net *net = dev_net(dev);
	struct lisp_net *lin = net_generic(net, lisp_net_id);

	switch (cmd) {
	case SIOCGETTUNNEL:
		tun = NULL;

		rcu_read_lock();
		if (dev == lin->fb_tunnel_dev) {
			if (copy_from_user(&parms, ifr->ifr_ifru.ifru_data,
					   sizeof(parms))) {
				err = -EFAULT;
				break;
			}
			tun = lisp_tunnel_lookup(net, parms.iph.saddr);
		}
		if (tun == NULL)
			tun = netdev_priv(dev);
		memcpy(&parms, &tun->parms, sizeof(parms));
		rcu_read_unlock();

		if (copy_to_user(ifr->ifr_ifru.ifru_data, &parms,
				 sizeof(parms)))
			err = -EFAULT;
		break;

	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		err = -EFAULT;
		if (copy_from_user(&parms, ifr->ifr_ifru.ifru_data,
				   sizeof(parms)))
			goto done;

		err = -EINVAL;
		if (parms.iph.version != 4 || parms.iph.protocol != IPPROTO_UDP ||
		    parms.iph.ihl != 5 || (parms.iph.frag_off&htons(~IP_DF)))
			goto done;

		rcu_read_lock();
		tun = lisp_tunnel_locate(net, &parms, cmd == SIOCADDTUNNEL);
		rcu_read_unlock();

		if (dev != lin->fb_tunnel_dev && cmd == SIOCCHGTUNNEL) {
			if (tun != NULL) {
				if (tun->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else {
				tun = netdev_priv(dev);
				lisp_tunnel_unlink(lin, tun);
				tun->parms.iph.saddr = parms.iph.saddr;
				memcpy(dev->dev_addr, &parms.iph.saddr, 4);
				lisp_tunnel_link(lin, tun);
				netdev_state_change(dev);
			}
		}

		if (tun) {
			err = 0;
			if (cmd == SIOCCHGTUNNEL) {
				tun->parms.iph.ttl = parms.iph.ttl;
				tun->parms.iph.tos = parms.iph.tos;
				}
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &tun->parms,
					 sizeof(parms)))
				err = -EFAULT;
		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;

	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		if (dev == lin->fb_tunnel_dev) {
			err = -EFAULT;
			if (copy_from_user(&parms, ifr->ifr_ifru.ifru_data,
					   sizeof(parms)))
				goto done;
			err = -ENOENT;
			tun = lisp_tunnel_lookup(net, parms.iph.saddr);
			if (tun == NULL)
				goto done;
			err = -EPERM;
			if (tun->dev == lin->fb_tunnel_dev)
				goto done;
		} else
			tun = netdev_priv(dev);

		lisp_tunnel_unlink(lin, tun);

		/* TODO: unset local flag in local mapping */

		unregister_netdevice(dev);
		err = 0;
		break;

	default:
		err = -EINVAL;
	}

done:
	return err;
}

/*****************************************************************************
 * LISP netlink interface
 *****************************************************************************/

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

	return 0;
out:
	return err;
}

static int lisp_gnl_doit_addmap(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct map_config mc;
	struct map_result mr;
	struct lisp_tunnel *tun;
	struct flowi fl;
	int err;

	err = lisp_parse_gnlparms(info, &mc);
	if (err)
		goto out;

	pr_debug("LISP: add map eid:%x/%d rloc:%x\n", mc.mc_dst,
		 mc.mc_dst_len, mc.mc_rloc->rloc);

	/* The mappings added manually are assumed to be usable
	   and rechable until verification */
	mc.mc_map_flags |= LISP_MAP_F_STATIC | LISP_MAP_F_UP;

	rcu_read_lock();

	/* check if rloc is local */
	tun = lisp_tunnel_lookup_dst(net, htonl(mc.mc_rloc->rloc));
	if (tun) {
		spin_lock_bh(&lin->lock);
		list_add_tail_rcu(&mc.mc_rloc->local_list, &lin->local_rlocs);
		spin_unlock_bh(&lin->lock);
		mc.mc_map_flags |= LISP_MAP_F_LOCAL;
	}

	/* if maping exists, add rloc to it */
	fl.fl4_dst = htonl(ntohl(mc.mc_dst));
	err = map_table_lookup(lin->maps, &fl, &mr);
	if (err != 1)
		if (mc.mc_dst_len == mr.prefixlen) {
			lisp_rloc_append(mr.map, mc.mc_rloc);
			rcu_read_unlock();
			return 0;
		}

	err = map_table_insert(lin->maps, &mc);

	rcu_read_unlock();
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
	struct lisp_net *lin = net_generic(net, lisp_net_id);
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

	cfg.mc_dst = cfg.mc_dst;
	cfg.mc_dst_len = cfg.mc_dst_len;
	rcu_read_lock();
	err = map_table_delete(lin->maps, &cfg);
	rcu_read_unlock();
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
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	int err;

	err = map_table_dump(lin->maps, &lisp_gnl_family, skb, cb);

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

/*****************************************************************************
 * LISP socket
 *****************************************************************************/

/* from udp.c */
static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return (!ipv6_only_sock(sk2)  &&
		 (!inet1->inet_rcv_saddr || !inet2->inet_rcv_saddr ||
		   inet1->inet_rcv_saddr == inet2->inet_rcv_saddr));
}

/* from udp.c */
static unsigned int udp4_portaddr_hash(struct net *net, __be32 saddr,
				       unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

/* from udp.c */
int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		udp4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		udp4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal, hash2_nulladdr);
}

/* based on inet_bind */
static int lisp_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct inet_sock *inet = inet_sk(sk);
	unsigned short snum;
	int chk_addr_ret;
	int err;

	err = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	chk_addr_ret = inet_addr_type(sock_net(sk), addr->sin_addr.s_addr);

	/* Not specified by any standard per-se, however it breaks too
	 * many applications when removed.  It is unfortunate since
	 * allowing applications to make a non-local bind solves
	 * several problems with systems using dynamic addressing.
	 * (ie. your servers still start up even if your ISDN link
	 *  is temporarily down)
	 */
	err = -EADDRNOTAVAIL;
	if (!sysctl_ip_nonlocal_bind &&
	    !(inet->freebind || inet->transparent) &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY) &&
	    chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST &&
	    chk_addr_ret != RTN_BROADCAST)
		goto out;

	snum = ntohs(addr->sin_port);
	err = -EACCES;
	if (snum && snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		goto out;

	/*      We keep a pair of addresses. rcv_saddr is the one
	 *      used by hash lookups, and saddr is used for transmit.
	 *
	 *      In the BSD API these are the same except where it
	 *      would be illegal to use them (multicast/broadcast) in
	 *      which case the sending device address is used.
	 */
	lock_sock(sk);

	/* Check these errors (active socket, double bind). */
	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */

	/* Make sure we are allowed to bind here. */
	if (sk->sk_prot->get_port(sk, snum)) {
		inet->inet_saddr = inet->inet_rcv_saddr = 0;
		err = -EADDRINUSE;
		goto out_release_sock;
	}

	if (inet->inet_rcv_saddr)
		sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
	if (snum)
		sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sk_dst_reset(sk);
	err = 0;

out_release_sock:
	release_sock(sk);
out:
	return err;
}

/*
* =0 if successfull or skb was discarded
* >0 if skb should be passed on to UDP
* <0 if skb should be resubmitted as proto -N
*/
int lisp_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct lisp_tunnel *tun;
	struct iphdr *iph = ip_hdr(skb);

	pr_debug("LISP: received %d bytes\n", skb->len);

	rcu_read_lock();

	tun = lisp_tunnel_lookup_dst(dev_net(skb->dev), iph->daddr);
	if (tun == NULL)
		goto drop;

	secpath_reset(skb);
	skb_pull(skb, sizeof(struct lisphdr) + sizeof(struct udphdr));
	skb_reset_network_header(skb);
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;

	skb_tunnel_rx(skb, tun->dev);

	netif_rx(skb);
	rcu_read_unlock();
	return 0;

drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return 0;
}

void lisp_destruct(struct sock *sk)
{
	(udp_sk(sk))->encap_type = 0;
	(udp_sk(sk))->encap_rcv = NULL;

	inet_sock_destruct(sk);
}

struct lisp_sock {
	struct udp_sock sk;
};

static struct proto lisp_proto = {
	.name		= "PF_LISP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct lisp_sock),
	.close		= udp_lib_close,
	.hash		= udp_lib_hash,
	.unhash		= udp_lib_unhash,
	.get_port	= udp_v4_get_port,
	.h.udp_table	= &udp_table,
};

static const struct proto_ops lisp_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= inet_release,
	.bind		= lisp_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= sock_no_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= sock_no_sendmsg,
	.recvmsg	= sock_no_recvmsg,
	.mmap		= sock_no_mmap,
};


static int lisp_create(struct net *net, struct socket *sock,
		       int protocol, int kern)
{
	int err;
	struct sock *sk = NULL;

	err = -ENOMEM;
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &lisp_proto);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);

	sock->state  = SS_UNCONNECTED;
	sock->ops    = &lisp_ops;

	lock_sock(sk);

	sk->sk_protocol = protocol;
	sk->sk_destruct = lisp_destruct;
	udp_sk(sk)->encap_type = LISP_ENCAPTYPE_UDP;
	udp_sk(sk)->encap_rcv = lisp_udp_encap_rcv;

	release_sock(sk);

	sk_refcnt_debug_inc(sk);

	err = 0;

out:
	return err;
}

static const struct net_proto_family lisp_proto_family = {
	.family	= PF_LISP,
	.create	= lisp_create,
	.owner	= THIS_MODULE,
};

/*****************************************************************************
 * LISP net device
 *****************************************************************************/
static void lisp_fill_hdr(struct net* net, struct sk_buff *skb)
{
	struct lisphdr *lh;
	struct rloc_entry *rloc;
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	int pos = 0;
	u32 lsb = 0;

	lh = (struct lisphdr *)skb_transport_header(skb);
	memset(lh, 0, sizeof(struct lisphdr));

	rcu_read_lock();

	list_for_each_entry_rcu(rloc, &lin->local_rlocs, local_list) {
		if (rloc->flags&LISP_RLOC_F_REACH)
			lsb |= 1 << pos;
		pos++;
		if (pos > 31)
			break;
	}

	rcu_read_unlock();

	lh->lsb_enable = 1;
	lh->lsb = htonl(lsb);
}

static netdev_tx_t lisp_tunnel_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct lisp_tunnel *tun = netdev_priv(dev);
	struct rtable *rt;
	struct net_device *tdev;
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct net *net = dev_net(dev);
	struct iphdr *tiph = &tun->parms.iph;
	u8     tos = tun->parms.iph.tos;
	__be16 df = tiph->frag_off;
	struct iphdr *old_iph = ip_hdr(skb);
	struct iphdr *iph;
	struct udphdr *uh;
	__be32 dst;
	unsigned int max_headroom;
	int data_len = skb->len;
	int udp_len;
	__wsum csum;
	int lisp_hlen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		sizeof(struct lisphdr);

	if (skb->protocol != htons(ETH_P_IP))
		goto tx_error;

	if (tos&1)
		tos = old_iph->tos;

	pr_debug("LISP: transmitting %d bytes\n", skb->len);

	{
		struct flowi fl = { .oif = 0,
				    .nl_u = { .ip4_u =
					      { .daddr = old_iph->daddr,
						.saddr = old_iph->saddr} },
				    .proto = old_iph->protocol };

		rcu_read_lock();
		dst = htonl(lisp_rloc_lookup(net, &fl));
		rcu_read_unlock();
		if (dst == 0)
			/* TODO: send a Map-Request (and packet cache?) */
			goto tx_drop;
	}

	{
		struct flowi fl = { .oif = 0,
				    .nl_u = { .ip4_u =
					      { .daddr = dst,
						.saddr = tiph->saddr} },
				    .proto = IPPROTO_UDP };
		if (ip_route_output_key(dev_net(dev), &rt, &fl)) {
			stats->tx_carrier_errors++;
			goto tx_error_icmp;
		}
	}

	tdev = rt->u.dst.dev;

	if (tdev == dev) {
		ip_rt_put(rt);
		stats->collisions++;
		goto tx_error;
	}

	df |= old_iph->frag_off & htons(IP_DF);

	max_headroom = LL_RESERVED_SPACE(tdev) + lisp_hlen;

	if (skb_headroom(skb) < max_headroom || skb_shared(skb) ||
	    (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (max_headroom > dev->needed_headroom)
			dev->needed_headroom = max_headroom;
		if (!new_skb) {
			ip_rt_put(rt);
			txq->tx_dropped++;
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
		old_iph = ip_hdr(skb);
	}

	/* LISP header */
	skb_push(skb, sizeof(struct lisphdr));
	skb_reset_transport_header(skb);
	lisp_fill_hdr(net, skb);

	/* UDP header */
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	uh		=	udp_hdr(skb);
	uh->source	=	htons(LISP_DATA_PORT);
	uh->dest	=	htons(LISP_DATA_PORT);
	udp_len		=	lisp_hlen + data_len - sizeof(struct iphdr);
	uh->len		=	htons(udp_len);
	uh->check	=	0;

	/* IP header */
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	iph		=	ip_hdr(skb);
	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->frag_off	=	df;
	iph->tos	=	INET_ECN_encapsulate(tos, old_iph->tos);
	iph->protocol	=	IPPROTO_UDP;
	iph->daddr	=	rt->rt_dst;
	iph->saddr	=	rt->rt_src;
	iph->ttl	=	tiph->ttl;

	if (iph->ttl == 0)
		iph->ttl =	old_iph->ttl;

	nf_reset(skb);


	/*TODO: make udp checksum calculation optional */
	if ((skb_dst(skb) && skb_dst(skb)->dev) &&
		 (!(skb_dst(skb)->dev->features & NETIF_F_V4_CSUM))) {
		skb->ip_summed = CHECKSUM_COMPLETE;
		csum = skb_checksum(skb, 0, udp_len, 0);
		uh->check = csum_tcpudp_magic(iph->saddr,
					      iph->daddr,
					      udp_len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(iph->saddr,
					       iph->daddr,
					       udp_len, IPPROTO_UDP, 0);
	}

	IPTUNNEL_XMIT();
	return NETDEV_TX_OK;

tx_error_icmp:
	dst_link_failure(skb);

tx_error:
	stats->tx_errors++;

tx_drop:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/* called by register_netdev */
static int lisp_tunnel_init(struct net_device *dev)
{
	struct lisp_tunnel *tun = netdev_priv(dev);

	tun->dev = dev;
	strcpy(tun->parms.name, dev->name);
	memcpy(dev->dev_addr, &tun->parms.iph.saddr, 4);

	return 0;
}

static const struct net_device_ops lisp_netdev_ops = {
	.ndo_start_xmit		= lisp_tunnel_xmit,
	.ndo_do_ioctl		= lisp_tunnel_ioctl,
	.ndo_init		= lisp_tunnel_init,
};

static void lisp_dev_setup(struct net_device *dev)
{
	dev->netdev_ops		= &lisp_netdev_ops;
	dev->destructor		= free_netdev;
	dev->type		= ARPHRD_LISP;
	dev->flags		= IFF_NOARP;
	dev->mtu		= ETH_DATA_LEN - sizeof(struct iphdr);
	dev->addr_len		= 4;
	dev->features		|= NETIF_F_NETNS_LOCAL;
}

/*****************************************************************************
 * Network namespace
 *****************************************************************************/

static int __net_init lisp_init_net(struct net *net)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	int err, i;

	for (i = 0; i < HASH_SIZE; ++i)
		INIT_LIST_HEAD(&lin->tunnels[i]);

	spin_lock_init(&lin->lock);
	INIT_LIST_HEAD(&lin->local_rlocs);
	lin->maps = map_hash_table();

	lin->fb_tunnel_dev = alloc_netdev(sizeof(struct lisp_tunnel), "lisp0",
					   lisp_dev_setup);
	if (!lin->fb_tunnel_dev) {
		err = -ENOMEM;
		goto err_alloc_dev;
	}

	dev_net_set(lin->fb_tunnel_dev, net);

	err = register_netdev(lin->fb_tunnel_dev);
	if (err)
		goto err_reg_dev;

	return 0;

err_reg_dev:
	free_netdev(lin->fb_tunnel_dev);
err_alloc_dev:
	return err;
}

static void lisp_destroy_tunnels(struct lisp_net *lin, struct list_head *list)
{
	int i;
	struct lisp_tunnel *tun;

	for (i = 0; i < HASH_SIZE; ++i) {
		list_for_each_entry_rcu(tun, &(lin->tunnels[i]),  list) {
			unregister_netdevice_queue(tun->dev, list);
		};
	};
}

static void __net_exit lisp_exit_net(struct net *net)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	int res;
	LIST_HEAD(list);

	spin_lock_bh(&lin->lock);
	rcu_read_lock();
	res = map_table_flush(lin->maps);
	pr_debug("flush: %d entries\n", res);
	spin_unlock_bh(&lin->lock);

	rtnl_lock();
	lisp_destroy_tunnels(lin, &list);
	unregister_netdevice_queue(lin->fb_tunnel_dev, &list);
	unregister_netdevice_many(&list);
	rtnl_unlock();
	rcu_read_unlock();
}

static struct pernet_operations lisp_net_ops = {
	.init	=	lisp_init_net,
	.exit	=	lisp_exit_net,
	.id	=	&lisp_net_id,
	.size	=	sizeof(struct lisp_net),
};

/*****************************************************************************
 * Init and cleanup
 *****************************************************************************/

static int __init lisp_init(void)
{
	int err;

	printk(KERN_INFO "LISP driver\n");

	err = register_pernet_device(&lisp_net_ops);
	if (err)
		goto out_unregister_pernet_dev;

	err = sock_register(&lisp_proto_family);
	if (err)
		goto out_unregister_sock;

	err = genl_register_family(&lisp_gnl_family);
	if (err)
		goto out_unregister_sock;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_addmap);
	if (err)
		goto out_unregister_nl;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_delmap);
	if (err)
		goto out_unregister_nl;

	err = genl_register_ops(&lisp_gnl_family, &lisp_gnl_ops_showmap);
	if (err)
		goto out_unregister_nl;

	map_hash_init();

out:
	return err;
out_unregister_nl:
	genl_unregister_family(&lisp_gnl_family);
out_unregister_sock:
	sock_unregister(PF_LISP);
out_unregister_pernet_dev:
	unregister_pernet_device(&lisp_net_ops);
	goto out;
}

static void __exit lisp_exit(void)
{
	genl_unregister_family(&lisp_gnl_family);
	unregister_pernet_device(&lisp_net_ops);
	sock_unregister(PF_LISP);
}

module_init(lisp_init);
module_exit(lisp_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Lorca <alex.lorca@gmail.com>");
MODULE_DESCRIPTION("LISP driver");
