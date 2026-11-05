/* Root helper: open one or more TUN queues and pass the fds back. */
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define TUNSETIFF 0x400454ca
#define IFF_TUN 0x0001
#define IFF_NO_PI 0x1000
#define IFF_MULTI_QUEUE 0x0100

static int bring_up(const char *name)
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		execl("/run/current-system/sw/bin/ip", "ip", "link", "set", name, "up", (char *)NULL);
		execlp("ip", "ip", "link", "set", name, "up", (char *)NULL);
		_exit(127);
	}
	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return status == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
	int count, i, sock;
	int fds[8];
	char name[IFNAMSIZ];
	struct sockaddr_un addr;
	char payload[IFNAMSIZ];
	char cbuf[CMSG_SPACE(sizeof(int) * 8)];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	if (argc != 3)
		return 2;
	count = atoi(argv[2]);
	if (count < 1 || count > 8)
		return 2;
	memset(name, 0, sizeof(name));
	for (i = 0; i < count; i++) {
		struct ifreq ifr;
		int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			perror("open /dev/net/tun");
			return 1;
		}
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
		if (count > 1)
			ifr.ifr_flags = (short)(ifr.ifr_flags | IFF_MULTI_QUEUE);
		if (i > 0)
			strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
		if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
			perror("TUNSETIFF");
			return 1;
		}
		if (i == 0)
			strncpy(name, ifr.ifr_name, IFNAMSIZ - 1);
		fds[i] = fd;
	}
	if (bring_up(name) != 0) {
		fprintf(stderr, "ip link set %s up failed\n", name);
		return 1;
	}
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return 1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		return 1;
	}
	memset(payload, 0, sizeof(payload));
	memcpy(payload, name, IFNAMSIZ);
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = payload;
	iov.iov_len = IFNAMSIZ;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(cbuf, 0, sizeof(cbuf));
	msg.msg_control = cbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)count);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)count);
	memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * (size_t)count);
	if (sendmsg(sock, &msg, 0) < 0) {
		perror("sendmsg");
		return 1;
	}
	return 0;
}
