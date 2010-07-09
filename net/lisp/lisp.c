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

#define PRINTK(_fmt, args...) printk(KERN_INFO "lisp: " _fmt, ##args)

#define LISP_ENCAPTYPE_UDP 1
#define HASH_SIZE        16
#define HASH(addr) (((__force u32)addr^((__force u32)addr>>4))&0xF)

static DEFINE_SPINLOCK(lisp_lock);

struct rloc_entry {
	struct list_head	list;
	__be32			rloc;
	int			priority;
	int 			weigth;
	char			rloc_flags;
};

struct map_entry {
	struct list_head	list;
	__be32			eid;
	struct list_head	rlocs;
	int 			rloc_cnt;
	char			map_flags;
};

struct lisp_tunnel {
	struct list_head	list;
	struct net_device	*dev;
	struct ip_tunnel_parm 	parms;
};

struct lisp_net {
	struct list_head tunnels[HASH_SIZE];
	struct list_head maps;
	struct net_device *fb_tunnel_dev;	/* Fallback tunnel */
};

static int lisp_net_id __read_mostly;

static void lisp_dev_setup(struct net_device *dev);

/* TODO: this lookup and the map structure need optimization*/
static struct lisp_tunnel *lisp_tunnel_lookup(struct net *net, u32 remote)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct net_device *dev;
	struct lisp_tunnel *t;
	unsigned h = HASH(remote);

	list_for_each_entry_rcu(t, &(lin->tunnels[h]),  list) {
		if (t->parms.iph.saddr == remote)
			return t;
	};

	dev = lin->fb_tunnel_dev;
	t = (struct lisp_tunnel *)netdev_priv(dev);
	if (t->parms.iph.saddr == remote)
		return t;

	return NULL;
}

static void lisp_tunnel_add(struct net *net, struct lisp_tunnel *tun)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	unsigned h = HASH(tun->parms.iph.saddr);

	list_add_tail_rcu(&tun->list, &lin->tunnels[h]);
}

static void lisp_tunnel_del(struct lisp_tunnel *tun)
{
	list_del_rcu(&tun->list);
}

static __be32 lisp_dst_lookup(struct net *net, __be32 dst)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	struct map_entry *map;
	struct rloc_entry *ret;

	list_for_each_entry_rcu(map, &(lin->maps),  list) {
		if (map->eid == dst && map->rloc_cnt > 0){
			ret = list_first_entry_rcu(&map->rlocs, struct rloc_entry, list);
			return ret->rloc;
		}
	};
	return -1;
}

static int lisp_tunnel_ioctl(struct net_device *dev, struct ifreq *ifr,
		int cmd)
{
	int err = 0;
	struct ip_tunnel_parm parms;
	struct lisp_tunnel *lt;
	struct net *net = dev_net(dev);
	char name[IFNAMSIZ];
	struct lisp_net *lin = net_generic(net, lisp_net_id);

	switch (cmd) {
	case SIOCGETTUNNEL:
		lt = NULL;
		if (dev == lin->fb_tunnel_dev) {
			if (copy_from_user(&parms, ifr->ifr_ifru.ifru_data, sizeof(parms))) {
				err = -EFAULT;
				break;
			}
			rcu_read_lock();
			lt = lisp_tunnel_lookup(net, parms.iph.saddr);
			rcu_read_unlock();
		}
		if (lt == NULL)
			lt = netdev_priv(dev);
		memcpy(&parms, &lt->parms, sizeof(parms));
		if (copy_to_user(ifr->ifr_ifru.ifru_data, &parms, sizeof(parms)))
			err = -EFAULT;
		break;

	case SIOCADDTUNNEL:
		err = -EPERM;
		if (!capable(CAP_NET_ADMIN))
			goto done;

		err = -EFAULT;
		if (copy_from_user(&parms, ifr->ifr_ifru.ifru_data, sizeof(parms)))
			goto done;

		err = -EINVAL;
		if (parms.iph.version != 4 || parms.iph.protocol != IPPROTO_UDP ||
		    parms.iph.ihl != 5 || (parms.iph.frag_off&htons(~IP_DF)))
			goto done;

		rcu_read_lock();
		lt = lisp_tunnel_lookup(net, parms.iph.saddr);
		rcu_read_unlock();

		if (lt) {
			err = -EEXIST;
			goto done;
		} else {
			if (parms.name[0])
				strlcpy(name, parms.name, IFNAMSIZ);
			else
				sprintf(name, "lisp%%d");

			dev = alloc_netdev(sizeof(struct lisp_tunnel), name,
					   lisp_dev_setup);
			dev_net_set(dev, net);

			if (strchr(name, '%')) {
				if (dev_alloc_name(dev, name) < 0)
					goto add_err;
			}
			lt = netdev_priv(dev);
			lt->dev = dev;
			memcpy(&(lt->parms), &parms, sizeof(parms));

			err = -EFAULT;
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &parms,
						sizeof(parms)))
				goto add_err;

			err = register_netdevice(dev);
			if (err < 0)
				goto add_err;

			spin_lock_bh(&lisp_lock);
			lisp_tunnel_add(net, lt);
			spin_unlock_bh(&lisp_lock);
		}
		err = 0;
		break;
add_err:
		free_netdev(dev);
		goto done;
	default:
		err = -EINVAL;
	}

done:
	return err;
}

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
int lisp_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct lisp_tunnel *tunnel;
	struct iphdr *iph = ip_hdr(skb);

	pr_debug("received %d bytes\n", skb->len);

	rcu_read_lock();

	tunnel = lisp_tunnel_lookup(dev_net(skb->dev), iph->saddr);
	if (tunnel == NULL)
	  goto drop;

	/*TODO: local map lookup*/

	secpath_reset(skb);
	skb_pull(skb, sizeof(struct lisphdr) + sizeof(struct udphdr));
	skb_reset_network_header(skb);
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;

	skb_tunnel_rx(skb, tunnel->dev);

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

	sk->sk_protocol	   = protocol;
	sk->sk_destruct	   = lisp_destruct;
	udp_sk(sk)->encap_type = LISP_ENCAPTYPE_UDP;
	udp_sk(sk)->encap_rcv = lisp_udp_encap_recv;

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

static netdev_tx_t lisp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct lisp_tunnel *tun = netdev_priv(dev);
	struct rtable *rt;
	struct net_device *tdev;
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct net *net = dev_net(dev);
	struct iphdr *tiph = &tun->parms.iph;
	struct iphdr *old_iph = ip_hdr(skb);
	struct iphdr *iph;
	struct udphdr *uh;
	struct lisphdr *lh;
	__be32 dst;
	int lisp_hlen =  sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct lisphdr);
	unsigned int max_headroom;
	int data_len = skb->len;
	int udp_len;
	__wsum csum;

	rcu_read_lock();
	dst = lisp_dst_lookup(net, old_iph->daddr);
	rcu_read_unlock();
	if (dst == -1)
		/* TODO: send a Map-Request (and packet cache?) */
		goto tx_drop;

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

	max_headroom = LL_RESERVED_SPACE(tdev) + lisp_hlen;

	if (skb_headroom(skb) < max_headroom || skb_shared(skb)||
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
	lh = lisp_hdr(skb);
	/* TODO: fill LISP header */

	/* UDP header */
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	uh		= 	udp_hdr(skb);
	uh->source	=	htons(LISP_DATA_PORT);
	uh->dest	= 	htons(LISP_DATA_PORT);
	udp_len 	=	lisp_hlen + data_len - sizeof(struct iphdr);
	uh->len 	= 	htons(udp_len);
	uh->check	=	0;

	/* IP header */
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);

	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	/* TODO: set frag_off, tos */
	iph		=	ip_hdr(skb);
	iph->version	=	4;
	iph->ihl	=	sizeof(struct iphdr) >> 2;
	iph->protocol	=	IPPROTO_UDP;
	iph->daddr	=	rt->rt_dst;
	iph->saddr	=	rt->rt_src;

	if ((iph->ttl = tiph->ttl) == 0)
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

static void lisp_tunnel_uninit(struct net_device *dev)
{
	dev_put(dev);
}

/* called by register_netdev */
static int lisp_tunnel_init(struct net_device *dev)
{
	struct lisp_tunnel *tunnel = netdev_priv(dev);

	tunnel->dev = dev;
	strcpy(tunnel->parms.name, dev->name);
	memcpy(dev->dev_addr, &tunnel->parms.iph.saddr, 4);
	dev_hold(dev);

	return 0;
}

static const struct net_device_ops lisp_netdev_ops = {
	.ndo_start_xmit		= lisp_dev_xmit,
	.ndo_do_ioctl		= lisp_tunnel_ioctl,
	.ndo_init		= lisp_tunnel_init,
	.ndo_uninit		= lisp_tunnel_uninit,
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

	INIT_LIST_HEAD(&lin->maps);

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
	struct lisp_tunnel *t;

	for (i = 0; i < HASH_SIZE; ++i) {
		list_for_each_entry_rcu(t, &(lin->tunnels[i]),  list) {
			unregister_netdevice_queue(t->dev, list);
		};
	};

}

static void __net_exit lisp_exit_net(struct net *net)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	LIST_HEAD(list);

	rtnl_lock();
	lisp_destroy_tunnels(lin, &list);
	unregister_netdevice_queue(lin->fb_tunnel_dev, &list);
	unregister_netdevice_many(&list);
	rtnl_unlock();
}

static struct pernet_operations lisp_net_ops = {
	.init = lisp_init_net,
	.exit = lisp_exit_net,
	.id   = &lisp_net_id,
	.size = sizeof(struct lisp_net),
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

out:
	return err;
out_unregister_sock:
	sock_unregister(PF_LISP);
out_unregister_pernet_dev:
	unregister_pernet_device(&lisp_net_ops);
	goto out;
}

static void __exit lisp_exit(void)
{
	unregister_pernet_device(&lisp_net_ops);
	sock_unregister(PF_LISP);
}

module_init(lisp_init);
module_exit(lisp_exit);
MODULE_LICENSE("GPL");
