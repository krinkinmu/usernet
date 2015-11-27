#ifndef __USERNET_H__
#define __USERNET_H__

#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/list.h>

#define USERNET_DEVICES     2
#define USERNET_TIMEOUT     5

struct usernet_device {
	struct miscdevice misc;
	struct net_device_stats stats;
	struct net_device *dev;
	struct list_head sent;
	struct list_head pool;
	spinlock_t lock;
};

struct usernet_packet {
	struct list_head head;
	char data[ETH_DATA_LEN];
	int len;
};

static inline struct usernet_device *USERNET(struct miscdevice *misc)
{ return container_of(misc, struct usernet_device, misc); }

static inline struct usernet_packet *PACKET(struct list_head *head)
{ return container_of(head, struct usernet_packet, head); }

static inline struct net_device *NETDEV(struct usernet_device *dev)
{ return dev->dev; }

#endif /*__SUERNET_H__*/
