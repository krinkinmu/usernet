#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

#define DEV_NAME0    "/dev/usernet0"
#define DEV_NAME1    "/dev/usernet1"
#define ERR(...)     fprintf(stderr, __VA_ARGS__)
#define ETH_DATA_LEN 4096
#define ETH_ALEN     6

struct thread_info {
	volatile sig_atomic_t *done;
	pthread_t thread;
	int fdin;
	int fdout;
};

struct ethhdr {
	unsigned char dst[ETH_ALEN];
	unsigned char src[ETH_ALEN];
	unsigned short proto;
} __attribute__((packed));

struct iphdr {
	unsigned char ver_hlen;
	unsigned char tos;
	unsigned short tlen;
	unsigned short id;
	unsigned short flags_offset;
	unsigned char ttl;
	unsigned char proto;
	unsigned short csum;
	unsigned int src;
	unsigned int dst;
} __attribute__((packed));

static volatile sig_atomic_t done;
static pthread_mutex_t iomux = PTHREAD_MUTEX_INITIALIZER;

static void handle_signal(int sig)
{
	(void)sig;

	done = 1;
}

static void dump_eth_addr(const char *data)
{
	printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", data[0], data[1],
		data[2], data[3], data[4], data[5]);
}

static void dump_ip_addr(unsigned int addr)
{
	printf("%03hhu.%03hhu.%03hhu.%03hhu", addr & 0xff, (addr >> 8) & 0xff,
		(addr >> 16) & 0xff, (addr >> 24) & 0xff);
}

static unsigned short csum(const void *data, int len)
{
	const unsigned char *buff = data;
	unsigned long sum = 0;
	int i;

	while (len > 1) {
		sum += *((unsigned short *) buff);
		if (sum & 0x80000000ul)
			sum = (sum & 0xfffful) + (sum >> 16);
		len -= 2;
		buff += 2;
	}

	if (len)
		sum += (unsigned short) *buff;

	while (sum >> 16)
		sum = (sum & 0xfffful) + (sum >> 16);

	return ~sum;
}

static void dump_packet(void *data, int size)
{
	struct ethhdr *ehdr = data;
	struct iphdr *ihdr = (void *)(ehdr + 1);
	int hdrlen;

	if (size < sizeof(*ehdr)) {
		ERR("too small for ethernet\n");
		return;
	}

	printf("ethernet header:\n");
	printf("\tsrc: "); dump_eth_addr(ehdr->src); printf("\n");
	printf("\tdst: "); dump_eth_addr(ehdr->dst); printf("\n");
	printf("\tproto: %hx\n", ntohs(ehdr->proto));

	if (size < sizeof(*ehdr) + sizeof(*ihdr)) {
		ERR("too small for IPv4\n");
		return;
	}

	if (ntohs(ehdr->proto) != 0x800)
		return;

	hdrlen = 4 * ((ihdr->ver_hlen & 0x0f));
	printf("IPv4 header (len %d):\n", hdrlen);
	printf("\tsrc: "); dump_ip_addr(ihdr->src); printf("\n");
	printf("\tdst: "); dump_ip_addr(ihdr->dst); printf("\n");
	printf("\tproto: %hhx\n", ihdr->proto);
	printf("\tcsum: %hx\n", ihdr->csum);
	printf("\tmy csum: %hx\n", csum(ihdr, hdrlen));
}

static void hack_packet(void *data, int size)
{
	struct ethhdr *ehdr = data;
	struct iphdr *ihdr = (void *)(ehdr + 1);

	if (size < sizeof(*ehdr) + sizeof(*ihdr))
		return;

	if (ntohs(ehdr->proto) != 0x800)
		return;

	ihdr->src ^= (1 << 16);
	ihdr->dst ^= (1 << 16);
	ihdr->csum = 0;
	ihdr->csum = csum(ihdr, 4 * (ihdr->ver_hlen & 0x0f));
}

static void *worker(void *data)
{
	struct thread_info *info = data;

	while (!(*info->done)) {
		char data[ETH_DATA_LEN];
		ssize_t len;

		len = read(info->fdin, data, sizeof(data));
		if (len < 0) {
			ERR("cannot read file %s (%s)", DEV_NAME0,
				strerror(errno));
			continue;
		}
		if (len > 0) {
			pthread_mutex_lock(&iomux);
			printf("thread %d received packet\n",
				(int)pthread_self());
			dump_packet(data, len);
			hack_packet(data, len);
			dump_packet(data, len);
			pthread_mutex_unlock(&iomux);
			if (write(info->fdout, data, len) != len)
				ERR("write failed!\n");
		}
	}

	return NULL;
}

int main()
{
	struct thread_info th0, th1;
	int fd0, fd1, ret;

	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGALRM, handle_signal);

	fd0 = open(DEV_NAME0, O_RDWR);
	if (-1 == fd0) {
		ERR("cannot open file %s (%s)\n", DEV_NAME0, strerror(errno));
		return 1;
	}

	fd1 = open(DEV_NAME1, O_RDWR);
	if (-1 == fd1) {
		ERR("cannot open file %s (%s)\n", DEV_NAME1, strerror(errno));
		close(fd0);
		return 1;
	}

	th0.fdin = th1.fdout = fd0;
	th0.fdout = th1.fdin = fd1;
	th0.done = th1.done = &done;

	ret = pthread_create(&th1.thread, NULL, &worker, &th1);
	if (!ret) {
		worker(&th0);
		pthread_join(th1.thread, NULL);
	} else {
		ERR("cannot create thread (%s)\n", strerror(ret));
	}	

	close(fd1);
	close(fd0);

	return ret ? 1 : 0;
}
