#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>

#include <linux/etherdevice.h>

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/fs.h>

#include "usernet.h"

static int timeout = USERNET_TIMEOUT;
module_param(timeout, int, 0);

static int poolsize = 8;
module_param(poolsize, int, 0);


static void usernet_pool_setup(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	int i;

	for (i = 0; i != poolsize; ++i) {
		struct usernet_packet *pkt = kmalloc(sizeof(*pkt), GFP_KERNEL);

		if (NULL == pkt) {
			netdev_err(dev, "ran out of memory\n");
			return;
		}
		list_add(&pkt->head, &priv->pool);
	}
}

static void usernet_pool_teardown(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, &priv->pool)
		kfree(PACKET(pos));
}

static void usernet_queue_drain(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);

	list_splice_init(&priv->sent, &priv->pool);
}

static struct usernet_packet *usernet_packet_get(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	struct list_head *pool = &priv->pool;
	struct usernet_packet *pkt;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	pkt = list_first_entry_or_null(pool, struct usernet_packet, head);
	if (pkt)
		list_del(&pkt->head);
	if (list_empty(pool))
		netif_stop_queue(dev);
	spin_unlock_irqrestore(&priv->lock, flags);
	return pkt;
}

static void usernet_packet_put(struct net_device *dev,
			struct usernet_packet *pkt)
{
	struct usernet_device *priv = netdev_priv(dev);
	struct list_head *pool = &priv->pool;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	list_add(&pkt->head, pool);
	spin_unlock_irqrestore(&priv->lock, flags);
	if (netif_queue_stopped(dev))
		netif_wake_queue(dev);
}

static int usernet_open(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct usernet_device *dev = USERNET(misc);

	if (netif_carrier_ok(NETDEV(dev))) {
		dev_warn(misc->this_device, "device has been opened already\n");
		return -EBUSY;
	}
	netif_carrier_on(NETDEV(dev));

	return 0;
}

static int usernet_release(struct inode *inode, struct file *file)
{
	struct miscdevice *misc = file->private_data;
	struct usernet_device *dev = USERNET(misc);

	netif_carrier_off(NETDEV(dev));

	return 0;
}

static ssize_t usernet_read(struct file *filep, char __user *data, size_t size,
			loff_t *offset)
{
	struct miscdevice *misc = filep->private_data;
	struct usernet_device *dev = USERNET(misc);
	struct net_device *netdev = NETDEV(dev);
	struct list_head *queue = &dev->sent;
	struct usernet_packet *pkt;
	unsigned long flags;
	ssize_t ret = 0;

	spin_lock_irqsave(&dev->lock, flags);
	pkt = list_first_entry_or_null(queue, struct usernet_packet, head);
	if (pkt)
		list_del(&pkt->head);
	spin_unlock_irqrestore(&dev->lock, flags);

	if (!pkt)
		return 0;

	if (size < pkt->len) {
		netdev_warn(netdev, "packet truncated\n");
		pkt->len = size;
	}

	if (copy_to_user(data, pkt->data, pkt->len))
		ret = -EFAULT;
	else
		ret = pkt->len;
	usernet_packet_put(netdev, pkt);

	return ret;
}

static ssize_t usernet_write(struct file *filep, const char __user *data,
			size_t size, loff_t *offset)
{
	struct miscdevice *misc = filep->private_data;
	struct usernet_device *dev = USERNET(misc);
	struct net_device *netdev = NETDEV(dev);
	struct sk_buff *skb;

	skb = netdev_alloc_skb_ip_align(netdev, size);
	if (!skb) {
		netdev_warn(netdev, "low on mem, packet dropped\n");
		dev->stats.rx_dropped++;
		return size;
	}

	if (copy_from_user(skb_put(skb, size), data, size)) {
		dev_kfree_skb_any(skb);
		return -EFAULT;
	}

	skb->dev = netdev;
	skb->protocol = eth_type_trans(skb, netdev);
	skb->ip_summed = CHECKSUM_NONE;
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += size;
	netif_rx(skb);

	return size;
}

static const struct file_operations usernet_fops = {
	.owner = THIS_MODULE,
	.open = usernet_open,
	.release = usernet_release,
	.read = usernet_read,
	.write = usernet_write
};

static int usernet_netdev_open(struct net_device *dev)
{
	memcpy(dev->dev_addr, "\0USRNT", ETH_ALEN);
	netif_start_queue(dev);

	return 0;
}

static int usernet_netdev_stop(struct net_device *dev)
{
	netif_stop_queue(dev);

	return 0;
}

static netdev_tx_t usernet_netdev_start_xmit(struct sk_buff *skb,
			struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	struct usernet_packet *pkt = usernet_packet_get(dev);
	unsigned long flags;

	if (!pkt) {
		netdev_warn(dev, "pool is empty\n");
		dev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
		goto drop;
	}

	memcpy(pkt->data, skb->data, skb->len);
	pkt->len = skb->len;
	dev_kfree_skb_any(skb);

	spin_lock_irqsave(&priv->lock, flags);
	list_add_tail(&pkt->head, &priv->sent);
	spin_unlock_irqrestore(&priv->lock, flags);

	dev->trans_start = jiffies;
	priv->stats.tx_packets++;
	priv->stats.tx_bytes = skb->len;

	return NETDEV_TX_OK;

drop:
	return NET_XMIT_DROP;
}

static void usernet_netdev_tx_timeout(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);

	netdev_warn(dev, "unexpected timeout\n");
	priv->stats.tx_errors++;
}

static struct net_device_stats *usernet_netdev_get_stats(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);

	return &priv->stats;
}

static const struct net_device_ops usernet_netdev_ops = {
	.ndo_open = usernet_netdev_open,
	.ndo_stop = usernet_netdev_stop,
	.ndo_start_xmit = usernet_netdev_start_xmit,
	.ndo_tx_timeout = usernet_netdev_tx_timeout,
	.ndo_get_stats = usernet_netdev_get_stats
};

static void usernet_netdev_init(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	struct miscdevice *misc = &priv->misc;

	memset(priv, 0, sizeof(*priv));
	misc->name = dev->name;
	misc->fops = &usernet_fops;
	misc->minor = MISC_DYNAMIC_MINOR;
	misc->mode = S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP;
	spin_lock_init(&priv->lock);
	INIT_LIST_HEAD(&priv->sent);
	INIT_LIST_HEAD(&priv->pool);
	usernet_pool_setup(dev);
	priv->dev = dev;

	ether_setup(dev);
	dev->watchdog_timeo = timeout;
	dev->netdev_ops = &usernet_netdev_ops;
	netif_carrier_off(dev);
}

static struct net_device *usernet_netdev_create(const char *name)
{
	struct net_device *dev;

	dev = alloc_netdev(sizeof(struct usernet_device), name,
		NET_NAME_UNKNOWN, usernet_netdev_init);

	return dev;
}

static int usernet_netdev_register(struct net_device *dev)
{
	struct usernet_device *priv = netdev_priv(dev);
	int ret;

	if ((ret = register_netdev(dev)))
		goto err;

	if ((ret = misc_register(&priv->misc))) {
		netif_tx_disable(dev);
		unregister_netdev(dev);
		goto err;
	}

	return 0;
err:
	netdev_err(dev, "error %d while registering \"%s\"\n",
		ret, dev->name);
	return -ENODEV;
}

static struct net_device *usernet_dev[USERNET_DEVICES];

static void usernet_finish(void)
{
	int i;

	for (i = 0; i != USERNET_DEVICES; ++i) {
		struct net_device *dev = usernet_dev[i];
		struct usernet_device *priv;

		if (!dev)
			continue;

		netif_tx_disable(dev);
		unregister_netdev(dev);
		priv = netdev_priv(dev);
	}
}

static void usernet_cleanup(void)
{
	int i;

	for (i = 0; i != USERNET_DEVICES; ++i) {
		struct net_device *dev = usernet_dev[i];
		struct usernet_device *priv;

		if (!dev)
			continue;

		usernet_dev[i] = NULL;
		priv = netdev_priv(dev);
		WARN_ON(netif_carrier_ok(dev));
		if (!netif_carrier_ok(dev)) {
			misc_deregister(&priv->misc);
			usernet_queue_drain(dev);
			usernet_pool_teardown(dev);
			free_netdev(dev);
		}
	}
}

int __init usernet_init(void)
{
	int i, ret;

	for (i = 0; i != USERNET_DEVICES; ++i) {
		char name[IFNAMSIZ];

		snprintf(name, IFNAMSIZ, "usernet%d", i);
		usernet_dev[i] = usernet_netdev_create(name);

		if (!usernet_dev[i]) {
			ret = -ENOMEM;
			goto err;
		}
	}

	for (i = 0; i != USERNET_DEVICES; ++i) {
		ret = usernet_netdev_register(usernet_dev[i]);

		if (ret)
			goto err;
	}

	return 0;

err:
	usernet_finish();
	usernet_cleanup();
	return ret;
}

void __exit usernet_exit(void)
{
	usernet_finish();
	usernet_cleanup();
}

module_init(usernet_init);
module_exit(usernet_exit);
MODULE_LICENSE("GPL");
