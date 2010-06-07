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

struct lisp_sock {
	struct sock sk;
};

static struct proto lisp_proto = {
	.name		= "PF_LISP",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct lisp_sock),
};

static const struct proto_ops lisp_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= lisp_release,
	.bind		= sock_no_bind,
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
	int error;
	struct sock *sk = NULL;

	error = -ENOMEM;
	sk = sk_alloc(net, PF_LISP, GFP_KERNEL, &lisp_proto);
	if (!sk)
		goto out;

	sock_init_data(sock, sk);

	sock->state  = SS_UNCONNECTED;
	sock->ops    = &lisp_ops;

	error = 0;

out:
	return error;
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
