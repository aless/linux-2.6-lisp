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
#include <net/tcp_states.h>
#include <net/inet_hashtables.h>

static int lisp_net_id __read_mostly;
struct lisp_net {
	struct net_device *lisp_dev;
};

/*****************************************************************************
 * LISP socket
 *****************************************************************************/

static int lisp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	lock_sock(sk);
	sock_orphan(sk);
	release_sock(sk);
	sock_put(sk);

	return 0;
}

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
	sk = sk_alloc(net, PF_LISP, GFP_KERNEL, &lisp_proto);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);

	sock->state  = SS_UNCONNECTED;
	sock->ops    = &lisp_ops;

	lock_sock(sk);

	sk->sk_protocol	   = protocol;
	sk->sk_destruct	   = inet_sock_destruct;

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

	goto tx_error;

tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops lisp_netdev_ops = {
	.ndo_start_xmit		= lisp_dev_xmit,
};

static void lisp_dev_setup(struct net_device *dev)
{
	dev->netdev_ops		= &lisp_netdev_ops;
	dev->destructor		= free_netdev;
	dev->type		= ARPHRD_ETHER;
	dev->flags		= IFF_NOARP;

	random_ether_addr(dev->dev_addr);
}

/*****************************************************************************
 * Network namespace
 *****************************************************************************/

static int __net_init lisp_init_net(struct net *net)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);
	int err;

	lin->lisp_dev = alloc_netdev(sizeof(struct lisp_net), "lisp0",
					   lisp_dev_setup);
	if (!lin->lisp_dev) {
		err = -ENOMEM;
		goto err_alloc_dev;
	}
	dev_net_set(lin->lisp_dev, net);

	err = register_netdev(lin->lisp_dev);
	if (err)
		goto err_reg_dev;

	return 0;

err_reg_dev:
	free_netdev(lin->lisp_dev);
err_alloc_dev:
	return err;
}

static void __net_exit lisp_exit_net(struct net *net)
{
	struct lisp_net *lin = net_generic(net, lisp_net_id);

	unregister_netdev(lin->lisp_dev);
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
