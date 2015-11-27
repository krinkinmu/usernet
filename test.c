#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

#define DEV_NAME0 "/dev/usernet0"
#define ERR(...) fprintf(stderr, __VA_ARGS__)
#define ETH_DATA_LEN 4096

static volatile sig_atomic_t done;
static int width = 16;

static void handle_signal(int sig)
{
	(void)sig;

	done = 1;
}

static void hexdump(const char *data, int size)
{
	int i;

	for (i = 0; i != size; ++i) {
		printf("%02hhx ", data[i]);
		if (0 == (i + 1) % width)
			printf("\n");
	}
	if (size % width)
		printf("\n");
}

int main()
{
	int fd0;

	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGALRM, handle_signal);

	fd0 = open(DEV_NAME0, O_RDWR);
	if (-1 == fd0) {
		ERR("cannot open file %s (%s)\n", DEV_NAME0, strerror(errno));
		return 1;
	}

	while (!done) {
		char data[ETH_DATA_LEN];
		ssize_t len;

		len = read(fd0, data, sizeof(data));
		if (len < 0) {
			ERR("cannot read file %s (%s)", DEV_NAME0,
				strerror(errno));
			continue;
		}
		if (len > 0) {
			puts("packet received:");
			hexdump(data, len);
		}
	}

	close(fd0);

	return 0;
}
